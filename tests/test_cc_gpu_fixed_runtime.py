import array
import hashlib
import importlib.util
import json
import os
import struct
from pathlib import Path
from unittest import mock

import pytest


RUNTIME_PATH = Path(__file__).parents[1] / "runtime" / "cathedral-job"
DOCKERFILE_PATH = Path(__file__).parents[1] / "runtime" / "Dockerfile"


def load_runtime():
    loader = importlib.machinery.SourceFileLoader("cathedral_cc_gpu_job", str(RUNTIME_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_runtime_image_build_pins_the_workload_attestation_audience():
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
    assert "ARG WORKLOAD_ATTESTATION_AUDIENCE" in dockerfile
    assert (
        "-X main.workloadAudience=${WORKLOAD_ATTESTATION_AUDIENCE}" in dockerfile
    )
    assert (
        'test "${WORKLOAD_ATTESTATION_AUDIENCE}" != "https://sts.google.com"'
        in dockerfile
    )


def test_terminal_fixture_has_bit_stable_commitments():
    input_raw = struct.pack("<4f", 1.0, -2.0, 3.5, 4.0)
    model_raw = struct.pack("<4f", 2.0, 0.5, -1.0, 3.0)
    output_raw = struct.pack("<4f", 2.0, -1.0, -3.5, 12.0)
    assert hashlib.sha256(input_raw).hexdigest() == (
        "c9e7f1cef2b38dec871fb2629a19e3c622d49ac96fa567d28bc8944e7ef1b028"
    )
    assert hashlib.sha256(model_raw).hexdigest() == (
        "4c8416b9091886168d1461628ef2f0c5d6bf72c26fa3bb269d31c467192dc40c"
    )
    assert hashlib.sha256(output_raw).hexdigest() == (
        "828993aa3b39eb4055ba3fae3cabba566c154209a22cb6c16e66478cf709cfe3"
    )
    values = array.array("f")
    values.frombytes(output_raw)
    assert [float(value).hex() for value in values] == [
        "0x1.0000000000000p+1",
        "-0x1.0000000000000p+0",
        "-0x1.c000000000000p+1",
        "0x1.8000000000000p+3",
    ]


def test_fixed_runtime_has_no_cuda_cpu_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    runtime = load_runtime()
    input_root = (tmp_path / "work").resolve()
    output_root = input_root / "outputs"
    output_root.mkdir(parents=True)
    (input_root / "input.bin").write_bytes(struct.pack("<4f", 1, -2, 3.5, 4))
    (input_root / "model.bin").write_bytes(struct.pack("<4f", 2, 0.5, -1, 3))
    os.chmod(input_root / "input.bin", 0o600)
    os.chmod(input_root / "model.bin", 0o600)
    monkeypatch.setenv("CATHEDRAL_INPUT_DIR", str(input_root))
    monkeypatch.setenv("CATHEDRAL_OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(runtime.sys, "argv", [str(RUNTIME_PATH)])
    with mock.patch.object(runtime.ctypes, "CDLL", side_effect=OSError("no libcuda")):
        with pytest.raises(runtime.CUDAError, match="driver library is unavailable"):
            runtime.main()
    assert list(output_root.iterdir()) == []


def test_result_writer_is_canonical_bounded_and_create_only(tmp_path: Path):
    runtime = load_runtime()
    document = {
        "schema": runtime.SCHEMA,
        "operation": runtime.OPERATION,
        "cuda_device_name": "NVIDIA H100 80GB HBM3",
        "cuda_driver_version": 12080,
        "element_count": 4,
        "input_sha256": "sha256:" + "1" * 64,
        "model_sha256": "sha256:" + "2" * 64,
        "gpu_output_sha256": "sha256:" + "3" * 64,
        "gpu_output_sum_f64_hex": "0x1.3000000000000p+3",
        "gpu_output_first_f32_hex": ["0x1.0000000000000p+1"],
    }
    runtime.write_result(tmp_path, document)
    raw = (tmp_path / "result.json").read_bytes()
    assert len(raw) <= 262_144
    assert raw == json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    with pytest.raises(FileExistsError):
        runtime.write_result(tmp_path, document)
