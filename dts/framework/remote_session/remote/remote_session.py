# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022-2023 University of New Hampshire

from abc import ABC, abstractmethod
from dataclasses import InitVar, dataclass, field
from pathlib import PurePath

from framework.config import NodeConfiguration
from framework.exception import RemoteCommandExecutionError
from framework.logger import DTSLOG
from framework.settings import SETTINGS


@dataclass(slots=True, frozen=True)
class CommandResult:
    """
    The result of remote execution of a command.
    """

    name: str
    command: str
    init_stdout: InitVar[str]
    init_stderr: InitVar[str]
    return_code: int
    stdout: str = field(init=False)
    stderr: str = field(init=False)

    def __post_init__(self, init_stdout: str, init_stderr: str) -> None:
        """Strip the whitespaces from stdout and stderr.

        The generated __init__ method uses object.__setattr__() when the dataclass is frozen,
        so that's what we use here as well.

        In order to get access to dataclass fields in the __post_init__ method,
        we have to type them as InitVars. These InitVars are included in the __init__ method's
        signature, so we have to exclude the actual stdout and stderr fields
        from the __init__ method's signature, so that we have the proper number of arguments.
        """
        object.__setattr__(self, "stdout", init_stdout.strip())
        object.__setattr__(self, "stderr", init_stderr.strip())

    def __str__(self) -> str:
        return (
            f"stdout: '{self.stdout}'\n"
            f"stderr: '{self.stderr}'\n"
            f"return_code: '{self.return_code}'"
        )


class RemoteSession(ABC):
    """
    The base class for defining which methods must be implemented in order to connect
    to a remote host (node) and maintain a remote session. The derived classes are
    supposed to implement/use some underlying transport protocol (e.g. SSH) to
    implement the methods. On top of that, it provides some basic services common to
    all derived classes, such as keeping history and logging what's being executed
    on the remote node.
    """

    name: str
    hostname: str
    ip: str
    port: int | None
    username: str
    password: str
    history: list[CommandResult]
    _logger: DTSLOG
    _node_config: NodeConfiguration

    def __init__(
        self,
        node_config: NodeConfiguration,
        session_name: str,
        logger: DTSLOG,
    ):
        self._node_config = node_config

        self.name = session_name
        self.hostname = node_config.hostname
        self.ip = self.hostname
        self.port = None
        if ":" in self.hostname:
            self.ip, port = self.hostname.split(":")
            self.port = int(port)
        self.username = node_config.user
        self.password = node_config.password or ""
        self.history = []

        self._logger = logger
        self._logger.info(f"Connecting to {self.username}@{self.hostname}.")
        self._connect()
        self._logger.info(f"Connection to {self.username}@{self.hostname} successful.")

    @abstractmethod
    def _connect(self) -> None:
        """
        Create connection to assigned node.
        """

    def send_command(
        self,
        command: str,
        timeout: float = SETTINGS.timeout,
        verify: bool = False,
        env: dict | None = None,
    ) -> CommandResult:
        """
        Send a command to the connected node using optional env vars
        and return CommandResult.
        If verify is True, check the return code of the executed command
        and raise a RemoteCommandExecutionError if the command failed.
        """
        self._logger.info(f"Sending: '{command}'" + (f" with env vars: '{env}'" if env else ""))
        result = self._send_command(command, timeout, env)
        if verify and result.return_code:
            self._logger.debug(
                f"Command '{command}' failed with return code '{result.return_code}'"
            )
            self._logger.debug(f"stdout: '{result.stdout}'")
            self._logger.debug(f"stderr: '{result.stderr}'")
            raise RemoteCommandExecutionError(command, result.return_code)
        self._logger.debug(f"Received from '{command}':\n{result}")
        self.history.append(result)
        return result

    @abstractmethod
    def _send_command(self, command: str, timeout: float, env: dict | None) -> CommandResult:
        """
        Use the underlying protocol to execute the command using optional env vars
        and return CommandResult.
        """

    def close(self, force: bool = False) -> None:
        """
        Close the remote session and free all used resources.
        """
        self._logger.logger_exit()
        self._close(force)

    @abstractmethod
    def _close(self, force: bool = False) -> None:
        """
        Execute protocol specific steps needed to close the session properly.
        """

    @abstractmethod
    def is_alive(self) -> bool:
        """
        Check whether the remote session is still responding.
        """

    @abstractmethod
    def copy_from(
        self,
        source_file: str | PurePath,
        destination_file: str | PurePath,
    ) -> None:
        """Copy a file from the remote Node to the local filesystem.

        Copy source_file from the remote Node associated with this remote
        session to destination_file on the local filesystem.

        Args:
            source_file: the file on the remote Node.
            destination_file: a file or directory path on the local filesystem.
        """

    @abstractmethod
    def copy_to(
        self,
        source_file: str | PurePath,
        destination_file: str | PurePath,
    ) -> None:
        """Copy a file from local filesystem to the remote Node.

        Copy source_file from local filesystem to destination_file
        on the remote Node associated with this remote session.

        Args:
            source_file: the file on the local filesystem.
            destination_file: a file or directory path on the remote Node.
        """
