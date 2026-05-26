"""
Docker-based sandbox executor.
Manages container lifecycle, resource limits, and output capture.
"""

import time
import tempfile
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

import docker
from docker.errors import DockerException, ImageNotFound, APIError
logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of sandbox execution."""

    status: str  # success, timeout, error, killed
    stdout: str
    stderr: str
    exit_code: Optional[int]
    execution_time: float
    container_status: str


class SandboxExecutor:
    """Executes Python code inside a Docker container with security restrictions."""

    def __init__(self, image_name: str):
        self.image_name = image_name
        self._init_docker_client()

    def _init_docker_client(self):
        """Initialize Docker client, handle errors gracefully."""
        try:
            self.docker_client = docker.from_env()
            # Test connection
            self.docker_client.ping()
            logger.info("Docker client connected.")
        except DockerException as e:
            logger.error(f"Docker not available: {e}")
            self.docker_client = None

    def execute(
        self,
        code: str,
        timeout_seconds: int = 10,
        memory_mb: int = 256,
        cpu_cores: float = 1.0,
        network_enabled: bool = False,
        filesystem_write_enabled: bool = False,
    ) -> ExecutionResult:
        """
        Execute code in sandbox container
        Args:
            code: Python code string
            timeout_seconds: Maximum execution time
            memory_mb: Memory limit in MB
            cpu_cores: CPU cores limit (e.g., 0.5, 1.0)
            network_enabled: Allow network access (default False for security)
            filesystem_write_enabled: Allow write to container filesystem (default False)
        """
        if not self.docker_client:
            return ExecutionResult(
                status="error",
                stdout="",
                stderr="Docker daemon not available. Please install Docker and ensure it is running.",
                exit_code=-1,
                execution_time=0.0,
                container_status="docker_unavailable",
            )

        if not self._ensure_image():
            return ExecutionResult(
                status="error",
                stdout="",
                stderr=f"Sandbox image '{self.image_name}' not found. Build it first.",
                exit_code=-1,
                execution_time=0.0,
                container_status="image_missing",
            )

        # Create temporary directory for code file
        with tempfile.TemporaryDirectory(prefix="saferun_") as tmpdir:
            tmp_path = Path(tmpdir)
            code_file = tmp_path / "script.py"
            code_file.write_text(code, encoding="utf-8")
            # Make script readable and directory traversable for the container user
            code_file.chmod(0o644)  # rw-r--r--
            tmp_path.chmod(0o755)  # drwxr-xr-x

            # Container configuration
            mem_limit = f"{memory_mb}m"
            nano_cpus = int(cpu_cores * 1e9) if cpu_cores else None
            pids_limit = 64
            read_only_rootfs = True
            user = "sandbox"  # non-root user (exists in the sandbox image)
            network_mode = "none" if not network_enabled else "bridge"
            # IMPORTANT: auto_remove=False so we can fetch logs before removal
            auto_remove = False
            mount_rw = filesystem_write_enabled
            mount_path = "/sandbox"

            cap_drop = ["ALL"]
            security_opt = ["no-new-privileges:true"]

            start_time = time.time()
            container = None
            try:
                # Run container (detached)
                container = self.docker_client.containers.run(
                    image=self.image_name,
                    command=["python", "-u", "/sandbox/script.py"],
                    mem_limit=mem_limit,
                    nano_cpus=nano_cpus,
                    pids_limit=pids_limit,
                    read_only=read_only_rootfs,
                    user=user,
                    network_disabled=not network_enabled,
                    network=network_mode,
                    auto_remove=auto_remove,
                    detach=True,
                    volumes={
                        tmpdir: {"bind": mount_path, "mode": "rw" if mount_rw else "ro"}
                    },
                    cap_drop=cap_drop,
                    security_opt=security_opt,
                    hostname="sandbox",
                    domainname="local",
                    privileged=False,
                )

                # Wait for completion with timeout
                result = container.wait(timeout=timeout_seconds)
                exit_code = result["StatusCode"]

                # Fetch logs (container still exists)
                stdout_logs = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
                stderr_logs = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )

                execution_time = time.time() - start_time
                status = "success" if exit_code == 0 else "error"

                return ExecutionResult(
                    status=status,
                    stdout=stdout_logs,
                    stderr=stderr_logs,
                    exit_code=exit_code,
                    execution_time=execution_time,
                    container_status="completed",
                )

            except docker.errors.ContainerError as e:
                execution_time = time.time() - start_time
                return ExecutionResult(
                    status="error",
                    stdout=e.stdout.decode() if e.stdout else "",
                    stderr=e.stderr.decode() if e.stderr else str(e),
                    exit_code=e.exit_code,
                    execution_time=execution_time,
                    container_status="container_error",
                )
            except docker.errors.APIError as e:
                logger.exception("Docker API error")
                return ExecutionResult(
                    status="error",
                    stdout="",
                    stderr=f"Docker API error: {str(e)}",
                    exit_code=-1,
                    execution_time=time.time() - start_time,
                    container_status="api_error",
                )
            except Exception as e:
                logger.exception("Unexpected sandbox error")
                return ExecutionResult(
                    status="error",
                    stdout="",
                    stderr=f"Unexpected error: {str(e)}",
                    exit_code=-1,
                    execution_time=time.time() - start_time,
                    container_status="exception",
                )
            finally:
                if container:
                    try:
                        container.remove(force=True)
                    except Exception:
                        pass

    def _ensure_image(self) -> bool:
        """Check if sandbox image exists, build if needed."""
        if self.docker_client is None:
            return False
        try:
            self.docker_client.images.get(self.image_name)
            return True
        except ImageNotFound:
            logger.info(f"Building sandbox image...")
            try:
                # Build from included Dockerfile
                sandbox_dir = Path(__file__).parent.parent.parent / "sandbox_image"
                self.docker_client.images.build(
                    path=str(sandbox_dir),
                    tag=self.image_name,
                    rm=True
                )
                return True
            except Exception as e:
                logger.error(f"Failed to build: {e}")
                return False