from pathlib import Path
import re
import subprocess
import sys
from typing import Any
import distro
from psutil import WINDOWS
import pytest
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.fim.patterns import MONITORING_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor

from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture()
def file_to_monitor(test_metadata: dict) -> Any:
    path = test_metadata.get('file_to_monitor')
    file.write_file(path) if path else None

    yield path

    file.remove_file(path) if path else None


@pytest.fixture()
def folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    file.create_folder(path) if path else None

    yield path

    file.delete_path_recursively(path) if path else None


@pytest.fixture()
def fill_folder_to_monitor(test_metadata: dict) -> None:
    path = test_metadata.get('folder_to_monitor')
    amount = test_metadata.get('files_amount')

    [file.write_file(Path(path, f'test{i}.log')) for i in range(amount)]

    yield

    [file.remove_file(Path(path, f'test{i}.log')) for i in range(amount)]
    

@pytest.fixture()
def start_monitoring() -> None:
    FileMonitor(WAZUH_LOG_PATH).start(generate_callback(MONITORING_PATH))


@pytest.fixture(scope='session', autouse=True)
def install_audit():
    """Automatically install auditd before test session on linux distros."""
    if sys.platform == WINDOWS:
        return

    # Check distro
    linux_distro = distro.id()

    if re.match(linux_distro, "centos"):
        package_management = "yum"
        audit = "audit"
        option = "--assumeyes"
    elif re.match(linux_distro, "ubuntu") or re.match(linux_distro, "debian"):
        package_management = "apt-get"
        audit = "auditd"
        option = "--yes"
    else:
        raise ValueError(
            f"Linux distro ({linux_distro}) not supported for install audit")

    subprocess.run([package_management, "install", audit, option], check=True)
    subprocess.run(["service", "auditd", "start"], check=True)
