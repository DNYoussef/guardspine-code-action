import os
import json
import wasmtime
from pathlib import Path
from wasmtime import Engine, Store, Module, Linker, WasiConfig, ExitTrap

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
        wasi.inherit_env()    # Pass ENV vars (PII_ENTROPY_THRESHOLD etc) directly!
        
        # Input/Output handling
        # We need to capture stdout.
        # And write text to stdin.
        
        # wasmtime-py WasiConfig allows providing files for stdin/stdout.
        # We can use temporary files or pipes.
        # For a clean implementation without disk I/O, we might need custom pipes,
        # but WasiConfig in python mostly takes paths or inheritance.
        # Let's use a pipe approach if possible, or temp files.
        # Actually, `wasi_config.set_stdin_string` exists in some bindings?
        # Checked docs: set_stdin_file, inherit_stdin.
        
        # Input/Output handling using temporary files
        # wasmtime-py WasiConfig expects file paths, not FDs.
        import tempfile

        with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as f_in, \
             tempfile.NamedTemporaryFile(mode='r+', delete=False, encoding='utf-8') as f_out:
            
            f_in_path = f_in.name
            f_out_path = f_out.name
            
            # Write input
            if not text.endswith("\n"):
                text += "\n"
            f_in.write(text)
            f_in.flush()
            # We don't need to keep f_in open, WASI opens it by path?
            # actually wasmtime usually opens the file.
            
        try:
            wasi.stdin_file = f_in_path
            wasi.stdout_file = f_out_path
            
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
                
            # Read output
            with open(f_out_path, 'r', encoding='utf-8') as f:
                output = f.read()
                
            return output.strip()
            
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"PII-Shield WASM Module failed: {str(e)}")
            raise RuntimeError("WASM processing failed") from e
        finally:
            # Cleanup
            if os.path.exists(f_in_path):
                os.remove(f_in_path)
            if os.path.exists(f_out_path):
                os.remove(f_out_path)

