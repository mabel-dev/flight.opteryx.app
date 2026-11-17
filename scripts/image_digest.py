"""Resolve a pushed image tag to the digest Cloud Run will run.

    GAR_TOKEN=... python scripts/image_digest.py <region>-docker.pkg.dev/<project>/<repo>/<image>:<tag>

Prints `<repository>@sha256:...` for the linux/amd64 image behind the tag.

A BuildKit push is usually an image INDEX - the amd64 image plus a provenance
attestation - and Cloud Run resolves an index to the platform image inside it
and records THAT digest on the revision. So the index digest a tag points at is
never what a revision reports. Deploying by the platform image's digest makes
the revision record exactly the string printed here, which is what lets the
deploy workflow prove the canary revision runs the image it just built.

Standard library only; reads the registry's v2 API with an access token.
"""

import json
import os
import sys
import urllib.request

ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}


def resolve(reference: str, token: str) -> str:
    repository, _, tag = reference.rpartition(":")
    if not repository or "/" in tag:
        raise ValueError(f"expected <host>/<path>:<tag>, got {reference!r}")
    host, _, path = repository.partition("/")
    request = urllib.request.Request(
        f"https://{host}/v2/{path}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": ACCEPT},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read())
        content_type = response.headers.get("Content-Type", "").split(";")[0]
        header_digest = response.headers.get("Docker-Content-Digest")

    if body.get("mediaType", content_type) in INDEX_TYPES:
        amd64 = [
            m["digest"]
            for m in body.get("manifests", [])
            if (m.get("platform") or {}).get("os") == "linux"
            and (m.get("platform") or {}).get("architecture") == "amd64"
        ]
        if len(amd64) != 1:
            raise ValueError(f"{reference}: expected one linux/amd64 image, found {amd64}")
        return f"{repository}@{amd64[0]}"

    if not header_digest:
        raise ValueError(f"{reference}: registry returned no Docker-Content-Digest")
    return f"{repository}@{header_digest}"


if __name__ == "__main__":
    if len(sys.argv) != 2 or not os.environ.get("GAR_TOKEN"):
        print(f"usage: GAR_TOKEN=... {sys.argv[0]} <image:tag>", file=sys.stderr)
        sys.exit(2)
    print(resolve(sys.argv[1], os.environ["GAR_TOKEN"]))
