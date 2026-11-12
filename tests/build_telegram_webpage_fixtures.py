"""Regenerate input-only fixtures with pinned official Java serializers.

Requires a developer JDK. Normal tests consume the frozen gzip and never fetch
sources. Existing platform archive supplies the pinned TL base and safe stubs.
"""
from pathlib import Path
import argparse
import base64
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile

UPSTREAM_SHA256 = "36333f97d944d6a356f703248480b0577c1aff1e5a748b695d8640b2a0f048dc"
BASE_ARCHIVE_SHA256 = "58249417c988cdd77dc5f310e05c1e5b3129d40ab526ffa1e4ba93598a03f025"
COMMIT = "4de548e79fed27f1a66fbdff84223321838fe925"
CLASSES = {
    "TL_photoEmpty": "Photo",
    "TL_messageMediaWebPage": "MessageMedia",
    "TL_messageMediaWebPage_layer165": "TL_messageMediaWebPage",
    "TL_webPage": "WebPage",
    "TL_webPage_layer107": "TL_webPage",
    "TL_webPageEmpty": "WebPage",
    "TL_webPageEmpty_layer165": "TL_webPageEmpty",
    "TL_webPagePending": "WebPage",
    "TL_webPagePending_layer165": "TL_webPagePending",
    "TL_webPageUrlPending": "WebPage",
}


def block(text, begin):
    start = text.index("{", begin)
    depth = 1
    end = start + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def produce(upstream, work, output):
    root = Path(__file__).resolve().parents[1]
    source = Path(upstream).read_bytes()
    if hashlib.sha256(source).hexdigest() != UPSTREAM_SHA256:
        raise ValueError("Pinned official TLRPC source changed")
    archive = root / "tests/fixtures/telegram-platforms/oracle-sources.tar.gz"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != BASE_ARCHIVE_SHA256:
        raise ValueError("Pinned platform oracle source archive changed")
    work, output = Path(work), Path(output)
    work.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    native = work / "java"
    native.mkdir()
    with tarfile.open(archive) as base:
        for member in base:
            if not member.name.startswith("producer/java-src/") or not member.isfile() or not member.name.endswith(".java"):
                continue
            relative = Path(member.name).relative_to("producer/java-src")
            if ".." in relative.parts:
                raise ValueError("Unsafe pinned native member")
            target = native / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base.extractfile(member).read())

    tl_path = native / "org/telegram/tgnet/TLRPC.java"
    reduced = tl_path.read_text(encoding="utf-8")
    declarations = [
        "public static final int " + ",".join(f"FLAG_{i}=1<<{i}" for i in range(32)) + ";",
        "public static class Photo extends TLObject { public long id; }",
        "public static class WebPage extends TLObject { public int flags,hash,date,embed_width,embed_height,duration;"
        "public long id; public boolean has_large_media,video_cover_photo; public Photo photo;"
        "public TLObject document,cached_page; public ArrayList<TLObject> attributes=new ArrayList<>();"
        "public String url,display_url,type,site_name,title,description,embed_url,embed_type,author; }",
    ]
    original = source.decode("utf-8")
    extracted = {}
    for name, parent in CLASSES.items():
        declaration = re.search(r"public static class " + name + r"\s+extends\s+", original)
        if declaration is None:
            raise ValueError("Missing official class " + name)
        body = block(original, declaration.start())
        constructor = re.search(r"public static final int constructor\s*=\s*(0x[0-9a-f]+);", body).group(1)
        method_start = re.search(r"public void serializeToStream\(OutputSerializedData stream\)", body).start()
        method = "public void serializeToStream(OutputSerializedData stream) " + block(body, method_start)
        extracted[name] = {"constructor": constructor, "serializer": method}
        fields = ("public WebPage webpage; public boolean force_large_media,force_small_media,manual,safe;"
                  if name == "TL_messageMediaWebPage" else "")
        declarations.append(f"public static class {name} extends {parent} {{ public static final int constructor={constructor};"
                            + fields + method + "}")
    reduced = reduced.rstrip()[:-1] + "\n" + "\n".join(declarations) + "\n}\n"
    tl_path.write_text(reduced, encoding="utf-8")
    producer = root / "tests/telegram_webpage_oracle/NativeWebPageOracle.java"
    (native / producer.name).write_bytes(producer.read_bytes())
    classes = work / "classes"
    classes.mkdir()
    java_sources = [str(path) for path in sorted(native.rglob("*.java"))]
    subprocess.run(["javac", "-encoding", "UTF-8", "-d", str(classes), *java_sources], check=True)
    raw = work / "native-output"
    subprocess.run(["java", "-cp", str(classes), "NativeWebPageOracle", str(raw)], check=True)
    cases = []
    for index in range(8):
        name = f"message-{index}"
        blob = (raw / (name + ".blob")).read_bytes()
        text = (raw / (name + ".text")).read_text(encoding="utf-8")
        cases.append(dict(name=name, id=7301 + index, uid=77, sender_id=77, date=1794001000 + index,
                          text=text, blob_b64=base64.b64encode(blob).decode("ascii"),
                          blob_sha256=hashlib.sha256(blob).hexdigest()))
    corpus = dict(schema=1, producer="official-native-java-serializers", commit=COMMIT,
                  upstream_sha256=UPSTREAM_SHA256, cases=cases)
    frozen = json.dumps(corpus, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    (output / "oracle.json.gz").write_bytes(gzip.compress(frozen, mtime=0))
    sources = {"java/" + path.relative_to(native).as_posix(): path.read_bytes()
               for path in sorted(native.rglob("*.java"))}
    sources["official-serializers.json"] = json.dumps(extracted, indent=2).encode("utf-8")
    sources["build_telegram_webpage_fixtures.py"] = Path(__file__).read_bytes()
    sources["LICENSE"] = (root / "tests/fixtures/telegram-cache-profiles/LICENSE").read_bytes()
    sources["NOTICE.txt"] = ("Official Telegram Android serializers, copyright Nikolai Kudashov, 2013-2018.\n"
                            "GPL version 2 or later. Pinned source commit " + COMMIT + ".\n").encode("utf-8")
    source_tar = io.BytesIO()
    with tarfile.open(fileobj=source_tar, mode="w") as packed:
        for name, data in sorted(sources.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            packed.addfile(info, io.BytesIO(data))
    (output / "oracle-sources.tar.gz").write_bytes(gzip.compress(source_tar.getvalue(), mtime=0))
    manifest = dict(schema=1, commit=COMMIT, upstream_sha256=UPSTREAM_SHA256,
                    source_url=f"https://github.com/DrKLO/Telegram/blob/{COMMIT}/TMessagesProj/src/main/java/org/telegram/tgnet/TLRPC.java",
                    cases=len(cases), producer_sha256=hashlib.sha256(producer.read_bytes()).hexdigest(),
                    files={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.iterdir())})
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    produce(args.upstream, args.work, args.output)
