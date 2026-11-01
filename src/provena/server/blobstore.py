"""Ciphertext storage backends for the hub.

The hub only ever stores bytes it has already checked (size and sha256 against the ledger), so a
backend is a dumb keyed store: uploads are spooled to a local temp file first and published as a
whole. Keys are always `<project>/<cid>` with both parts validated as hex.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Protocol

from fastapi.responses import FileResponse, Response, StreamingResponse

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def _check(project: str, cid: str) -> None:
    if not (_HEX64.match(project) and _HEX64.match(cid)):
        raise ValueError("project and cid must be hex sha256")


class BlobStore(Protocol):
    def exists(self, project: str, cid: str) -> bool: ...
    def new_upload(self, project: str, cid: str) -> Path: ...
    def publish(self, project: str, cid: str, tmp: Path) -> None: ...
    def delete(self, project: str, cid: str) -> None: ...
    def response(self, project: str, cid: str) -> Response: ...
    def open(self, project: str, cid: str): ...
    def sweep(self) -> int: ...


class FsBlobStore:
    """`<root>/<project>/<cid[:2]>/<cid>`; temp files live next to their destination so the
    final rename is atomic."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def path(self, project: str, cid: str) -> Path:
        _check(project, cid)
        return self.root / project / cid[:2] / cid

    def exists(self, project: str, cid: str) -> bool:
        return self.path(project, cid).exists()

    def new_upload(self, project: str, cid: str) -> Path:
        dest = self.path(project, cid)
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest.parent, suffix=".part")
        os.close(fd)
        return Path(tmp)

    def publish(self, project: str, cid: str, tmp: Path) -> None:
        os.replace(tmp, self.path(project, cid))

    def delete(self, project: str, cid: str) -> None:
        self.path(project, cid).unlink(missing_ok=True)

    def response(self, project: str, cid: str) -> Response:
        return FileResponse(self.path(project, cid), media_type="application/octet-stream")

    def open(self, project: str, cid: str):
        return open(self.path(project, cid), "rb")

    def sweep(self) -> int:
        leftovers = list(self.root.rglob("*.part"))
        for leftover in leftovers:
            leftover.unlink(missing_ok=True)
        return len(leftovers)


class S3BlobStore:
    """S3-compatible object storage (AWS S3, DigitalOcean Spaces, MinIO, R2). Credentials come
    from the standard AWS environment/config chain, never from Provena's own configuration."""

    def __init__(self, bucket: str, *, prefix: str = "provena/", spool_dir: Path,
                 endpoint_url: str | None = None, client=None):
        if client is None:
            import boto3  # optional dependency: pip install "provena-ledger[s3]"

            client = boto3.client("s3", endpoint_url=endpoint_url)
        self.client, self.bucket, self.prefix = client, bucket, prefix
        self.spool_dir = spool_dir
        spool_dir.mkdir(parents=True, exist_ok=True)

    def key(self, project: str, cid: str) -> str:
        _check(project, cid)
        return f"{self.prefix}{project}/{cid}"

    def exists(self, project: str, cid: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self.client.head_object(Bucket=self.bucket, Key=self.key(project, cid))
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("404", "NoSuchKey", "NotFound"):
                return False
            if code in ("403", "AccessDenied"):  # S3 answers 403 for missing keys without List
                raise RuntimeError("S3 denied HeadObject: grant the hub s3:ListBucket on the "
                                   "bucket (and s3:GetObject/PutObject/DeleteObject)") from exc
            raise

    def new_upload(self, project: str, cid: str) -> Path:
        self.key(project, cid)
        fd, tmp = tempfile.mkstemp(dir=self.spool_dir, suffix=".part")
        os.close(fd)
        return Path(tmp)

    def publish(self, project: str, cid: str, tmp: Path) -> None:
        self.client.upload_file(str(tmp), self.bucket, self.key(project, cid))
        Path(tmp).unlink(missing_ok=True)

    def delete(self, project: str, cid: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=self.key(project, cid))

    def open(self, project: str, cid: str):
        return self.client.get_object(Bucket=self.bucket, Key=self.key(project, cid))["Body"]

    def response(self, project: str, cid: str) -> Response:
        body = self.client.get_object(Bucket=self.bucket, Key=self.key(project, cid))["Body"]
        return StreamingResponse(body.iter_chunks(1 << 20),
                                 media_type="application/octet-stream")

    def sweep(self) -> int:
        leftovers = list(self.spool_dir.glob("*.part"))
        for leftover in leftovers:
            leftover.unlink(missing_ok=True)
        return len(leftovers)
