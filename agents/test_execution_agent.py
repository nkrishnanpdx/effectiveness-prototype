import docker
import os
from langchain.tools import tool

class TestExecutor:
    def __init__(self):
        self.client = docker.from_env()

    @tool
    def execute_docker_test(self, image_name: str, test_script_content: str, container_port: int = None, host_port: int = None) -> dict:
        """
        Runs a test script within a specified Docker container image.
        The test_script_content is written to a temporary file and mounted into the container.
        Returns the container's stdout, stderr, and exit code.
        """
        container_name = f"cve-test-{os.urandom(4).hex()}"
        temp_script_path = f"/tmp/test_script_{os.urandom(8).hex()}.py"

        # Write the test script content to a temporary file
        try:
            with open(temp_script_path, "w") as f:
                f.write(test_script_content)
            os.chmod(temp_script_path, 0o755) # Make it executable
        except IOError as e:
            return {"error": f"Failed to write test script to temporary file: {e}"}

        ports_mapping = {}
        if container_port and host_port:
            ports_mapping = {f'{container_port}/tcp': host_port}

        try:
            # Pull the image first to ensure it's available [169, 170]
            print(f"Pulling Docker image: {image_name}...")
            self.client.images.pull(image_name)
            print(f"Image {image_name} pulled successfully.")

            # Run the container with the script mounted as a volume [158, 171, 172, 166]
            # Use a non-root user and resource limits for security [158, 166]
            container = self.client.containers.run(
                image_name,
                detach=True,
                name=container_name,
                volumes={temp_script_path: {'bind': '/app/test_script.py', 'mode': 'ro'}}, # Read-only mount [158]
                ports=ports_mapping,
                # user='nonrootuser', # Requires image to have this user
                # mem_limit='512m', # Example resource limit
                # network_mode='none' # Highly isolated, but might break network-dependent PoCs
            )
            print(f"Container {container_name} started. Executing test script...")

            # Execute the script inside the container [173, 158]
            # Pass arguments if needed, e.g., python /app/test_script.py arg1 arg2 [174, 175]
            exec_result = container.exec_run(
                cmd="python /app/test_script.py",
                stream=False,
                demux=True # Get stdout and stderr separately [176]
            )
            
            stdout = exec_result.output.decode('utf-8') if exec_result.output else ""
            stderr = exec_result.output.[1]decode('utf-8') if exec_result.output[1] else ""
            exit_code = exec_result.exit_code

            print(f"Test execution completed for {cve_id}. Stopping container...")
            container.stop()
            container.remove()
            print(f"Container {container_name} stopped and removed.")

            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "status": "success" if exit_code == 0 else "failed"
            }
        except docker.errors.ImageNotFound:
            return {"error": f"Docker image '{image_name}' not found. Please ensure it exists."}
        except docker.errors.APIError as e:
            return {"error": f"Docker API error: {e}"}
        except Exception as e:
            return {"error": f"An unexpected error occurred during Docker execution: {e}"}
        finally:
            # Clean up the temporary script file
            if os.path.exists(temp_script_path):
                os.remove(temp_script_path)

# Instantiate the class to make its methods callable as tools
test_execution_tool = TestExecutor().execute_docker_test
