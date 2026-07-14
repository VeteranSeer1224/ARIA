"""
PRD 05 — Fine-Tuning: LoRA/PEFT supervised fine-tuning of a base causal LM
(LLaMA 3 by default) to produce the "ARIA Tuned" condition in the evaluation
matrix.

The task the model is tuned for: turn raw scanner output into a structured
penetration-testing finding with a correct CVSS v3.1 vector. This is exactly
what the RQS rubric (evaluation.md §2C) rewards, so a tuned model should beat
the base model on CVSS correctness and report quality.

All heavy dependencies (torch, transformers, peft) are imported lazily inside
the functions that need them, so this module imports fine on a machine with
only pydantic installed — training simply raises a clear error if the deps are
absent. Mirrors the offline-safe pattern in memory.EmbeddingModel.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional


# ── Config ───────────────────────────────────────────────────────

@dataclass
class FineTuneConfig:
    """Hyperparameters for a LoRA SFT run."""
    base_model: str = "meta-llama/Meta-Llama-3-8B-Instruct"
    output_dir: str = field(
        default_factory=lambda: os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", "models", "aria-tuned"
        )
    )
    # LoRA
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    target_modules: List[str] = field(
        default_factory=lambda: ["q_proj", "k_proj", "v_proj", "o_proj"]
    )
    # Training
    epochs: int = 3
    learning_rate: float = 2e-4
    batch_size: int = 1
    grad_accum: int = 8
    max_seq_len: int = 1024
    # Runtime
    load_in_4bit: bool = True
    seed: int = 42


# ── Dependency guard ─────────────────────────────────────────────

def deps_available() -> bool:
    """True if torch + transformers + peft are importable (no GPU check)."""
    import importlib.util
    return all(
        importlib.util.find_spec(m) is not None
        for m in ("torch", "transformers", "peft")
    )


def _require_deps():
    if not deps_available():
        raise RuntimeError(
            "Fine-tuning requires torch, transformers, and peft. Install with:\n"
            "  pip install torch transformers peft\n"
            "(and bitsandbytes if load_in_4bit=True). These are intentionally not "
            "imported at module load so the ML package works without a GPU box."
        )


# ── Dataset ──────────────────────────────────────────────────────

# LLaMA 3 instruct chat template. Kept as a literal fallback so we do not
# depend on the tokenizer's apply_chat_template being present.
_SYSTEM = (
    "You are ARIA's finding formatter. Convert raw security-scanner output into a "
    "single JSON penetration-testing finding with a valid CVSS v3.1 vector string."
)


def format_example(instruction: str, output: str, input_text: str = "") -> str:
    """Render one training example as a LLaMA 3 instruct conversation string."""
    user = instruction if not input_text else f"{instruction}\n\n{input_text}"
    return (
        "<|begin_of_text|>"
        f"<|start_header_id|>system<|end_header_id|>\n\n{_SYSTEM}<|eot_id|>"
        f"<|start_header_id|>user<|end_header_id|>\n\n{user}<|eot_id|>"
        f"<|start_header_id|>assistant<|end_header_id|>\n\n{output}<|eot_id|>"
    )


def load_dataset(path: str) -> List[dict]:
    """
    Load a JSONL fine-tuning dataset. Each line must be an object with keys
    'instruction', 'output', and optionally 'input'. Returns the raw records
    (pure — no torch needed, so it is unit-testable).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}")
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "instruction" not in obj or "output" not in obj:
                raise ValueError(
                    f"{path}:{lineno} missing required 'instruction'/'output' keys"
                )
            records.append(obj)
    if not records:
        raise ValueError(f"Dataset {path} is empty")
    return records


def build_texts(records: List[dict]) -> List[str]:
    """Turn raw records into rendered training strings (pure, testable)."""
    return [
        format_example(r["instruction"], r["output"], r.get("input", ""))
        for r in records
    ]


# ── Training ─────────────────────────────────────────────────────

def train(config: FineTuneConfig, dataset_path: str) -> str:
    """
    Run LoRA SFT and save the adapter to config.output_dir. Returns the adapter
    path. Raises RuntimeError if ML deps are missing.

    ponytail: full-sequence causal-LM loss (prompt tokens are not masked). Fine
    for a small instruct SFT; add response-only masking if the model starts
    parroting prompts.
    """
    _require_deps()

    import torch
    from torch.utils.data import Dataset
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
        DataCollatorForLanguageModeling,
    )
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

    records = load_dataset(dataset_path)
    texts = build_texts(records)

    tokenizer = AutoTokenizer.from_pretrained(config.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    class _JsonlDataset(Dataset):
        def __init__(self, texts, tok, max_len):
            self.enc = [
                tok(t, truncation=True, max_length=max_len, padding=False)
                for t in texts
            ]

        def __len__(self):
            return len(self.enc)

        def __getitem__(self, i):
            item = {k: torch.tensor(v) for k, v in self.enc[i].items()}
            return item

    dataset = _JsonlDataset(texts, tokenizer, config.max_seq_len)

    model_kwargs = {"device_map": "auto"}
    if config.load_in_4bit:
        from transformers import BitsAndBytesConfig
        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
        )
    model = AutoModelForCausalLM.from_pretrained(config.base_model, **model_kwargs)

    if config.load_in_4bit:
        model = prepare_model_for_kbit_training(model)

    lora = LoraConfig(
        r=config.lora_r,
        lora_alpha=config.lora_alpha,
        lora_dropout=config.lora_dropout,
        target_modules=config.target_modules,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()

    args = TrainingArguments(
        output_dir=config.output_dir,
        num_train_epochs=config.epochs,
        per_device_train_batch_size=config.batch_size,
        gradient_accumulation_steps=config.grad_accum,
        learning_rate=config.learning_rate,
        fp16=True,
        logging_steps=10,
        save_strategy="epoch",
        seed=config.seed,
        report_to=[],
    )
    collator = DataCollatorForLanguageModeling(tokenizer, mlm=False)

    trainer = Trainer(model=model, args=args, train_dataset=dataset, data_collator=collator)
    trainer.train()

    os.makedirs(config.output_dir, exist_ok=True)
    model.save_pretrained(config.output_dir)
    tokenizer.save_pretrained(config.output_dir)
    print(f"[FineTune] Saved LoRA adapter to {config.output_dir}")
    return config.output_dir


# ── Inference ────────────────────────────────────────────────────

class TunedModel:
    """
    Loads a base model + LoRA adapter for inference. Used by the evaluation
    pipeline as the 'ARIA Tuned' condition. Base model (no adapter) gives the
    'ARIA Base' condition — pass adapter_dir=None.
    """

    def __init__(self, base_model: str, adapter_dir: Optional[str] = None):
        _require_deps()
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.tokenizer = AutoTokenizer.from_pretrained(base_model)
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        self.model = AutoModelForCausalLM.from_pretrained(
            base_model, device_map="auto", torch_dtype=torch.float16
        )
        if adapter_dir:
            from peft import PeftModel
            self.model = PeftModel.from_pretrained(self.model, adapter_dir)
        self.model.eval()

    def generate(self, instruction: str, input_text: str = "", max_new_tokens: int = 512) -> str:
        import torch
        prompt = format_example(instruction, "", input_text).rsplit("<|eot_id|>", 1)[0]
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            out = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id,
            )
        text = self.tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        return text.strip()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="ARIA LoRA fine-tuning")
    p.add_argument("--dataset", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data", "finetune_sample.jsonl"))
    p.add_argument("--base-model", default=FineTuneConfig.base_model)
    p.add_argument("--output-dir", default=None)
    args = p.parse_args()
    cfg = FineTuneConfig(base_model=args.base_model)
    if args.output_dir:
        cfg.output_dir = args.output_dir
    train(cfg, args.dataset)
