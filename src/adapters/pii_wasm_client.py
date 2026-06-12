import os
import wasmtime
from pathlib import Path
from wasmtime import Engine, Store, Module, Linker, WasiConfig

class PIIWasmClient:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PIIWasmClient, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self.engine = Engine()
        
        # Load WASM module
        base_path = Path(__file__).parent.parent.parent
        wasm_path = base_path / "lib" / "pii-shield.wasm"
        
        if not wasm_path.exists():
            # Fallback for different install layouts
            wasm_path = Path("lib/pii-shield.wasm")
            
        if not wasm_path.exists():
             raise RuntimeError(f"Could not find pii-shield.wasm at {wasm_path.absolute()}")

        self.module = Module.from_file(self.engine, str(wasm_path))
        self.linker = Linker(self.engine)
        self.linker.define_wasi()

    def _wasi_env(self) -> list[tuple[str, str]]:
        """Return the minimal non-secret environment the WASM detector needs."""
        allowed_names = {
            "PII_ENTROPY_THRESHOLD",
            "PII_SAFE_REGEX_LIST",
            "PII_SHIELD_SALT_FINGERPRINT",
        }
        return [
            (name, value)
            for name, value in os.environ.items()
            if name in allowed_names
        ]

    def _bind_ephemeral_stdin(self, wasi: WasiConfig, text: str) -> str:
        """Bind stdin from a temp file, then unlink the path immediately.

        wasmtime-py only accepts a filesystem path for stdin. The setter opens
        the file immediately, so removing the path after binding keeps the WASI
        handle readable without leaving plaintext behind for a later crash.
        """
        import tempfile

        if not text.endswith("\n"):
            text += "\n"

        with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as f_in:
            f_in_path = f_in.name
            f_in.write(text)
            f_in.flush()

        try:
            wasi.stdin_file = f_in_path
        finally:
            if os.path.exists(f_in_path):
                os.remove(f_in_path)

        return f_in_path

    def redact(self, text: str) -> str:
        # Each call needs a fresh store/WASI context because the Go runtime 
        # executes main() and exits, or processes a stream.
        # Our main_wasi.go loops over stdin.
        # We can try to keep one instance alive and pipe into it, 
        # but managing persistent pipes with wasmtime-py can be complex.
        # Simplest consistent approach: One-shot execution for now, 
        # OR keep an instance alive if we can write to its stdin buffer.
        
        # Let's try One-Shot execution first for safety and simplicity, 
        # providing the text as stdin.
        # Main_wasi.go expects lines.
        
        # NOTE: Re-instantiating the Go runtime for every string might be slow (10-50ms overhead).
        # But it avoids complex state management of the Go heap.
        # Optimization: We can reuse the Engine and Module (done in __init__).
        
        store = Store(self.engine)
        
        # Configure WASI
        wasi = WasiConfig()
        wasi.inherit_stderr() # Useful for debugging
        wasi.env = self._wasi_env()
        
        stdout_chunks: list[bytes] = []

        try:
            self._bind_ephemeral_stdin(wasi, text)
            wasi.stdout_custom = lambda chunk: stdout_chunks.append(chunk) or len(chunk)

            store.set_wasi(wasi)
            instance = self.linker.instantiate(store, self.module)
            
            start = instance.exports(store)["_start"]
            try:
                start(store)
            except wasmtime.ExitTrap as e:
                # All other codes (e.g., 1 or 2 on Go panic) must raise an error.
                if e.code != 0:
                    import logging
                    logging.getLogger(__name__).error(f"PII-Shield WASM Module failed: {str(e)}")
                    raise RuntimeError("WASM processing failed") from e
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"PII-Shield WASM Module failed: {str(e)}")
                raise RuntimeError("WASM processing failed") from e
                
            output = b"".join(stdout_chunks).decode("utf-8")
            return output.strip()
            
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"PII-Shield WASM Module failed: {str(e)}")
            raise RuntimeError("WASM processing failed") from e

