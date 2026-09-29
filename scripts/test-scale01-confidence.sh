#!/usr/bin/env bash
set -euo pipefail

scratch="$(mktemp -d "${TMPDIR:-/tmp}/smf-scale01.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
repo="$scratch/spark-sas7bdat"
artifacts="$scratch/artifacts"
mkdir -p "$artifacts"

curl --fail --location --silent --show-error \
  https://repo1.maven.org/maven2/io/github/saurfang/spark-sas7bdat_2.12/3.0.0/spark-sas7bdat_2.12-3.0.0.jar \
  --output "$artifacts/published-spark-sas7bdat_2.12-3.0.0.jar"
echo "a4240d930e37d0bd2b8223e2b0186d26ecaa6dbf65226865227d3a2f71802d0e  $artifacts/published-spark-sas7bdat_2.12-3.0.0.jar" | shasum -a 256 -c -
if unzip -Z1 "$artifacts/published-spark-sas7bdat_2.12-3.0.0.jar" | grep -q '\.class$'; then
  echo "published Scala 2.12 artifact unexpectedly contains classes" >&2
  exit 1
fi

git clone --quiet https://github.com/saurfang/spark-sas7bdat.git "$repo"
git -C "$repo" checkout --quiet dad0840bd89b7581c35a41ce372c61dc42d15eab
cp "$repo/LICENSE" "$artifacts/LICENSE.spark-sas7bdat"
echo "5f3e56904af6912d99cb1a569bed78e39ff6ea25301b7a8fccae5b6e5b62c3cc  $artifacts/LICENSE.spark-sas7bdat" | shasum -a 256 -c -

curl --fail --location --silent --show-error \
  https://raw.githubusercontent.com/epam/parso/3c514e66264f5f3d5b2970bc2509d749065630c0/LICENSE \
  --output "$artifacts/LICENSE.parso"
echo "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd  $artifacts/LICENSE.parso" | shasum -a 256 -c -

curl --fail --location --silent --show-error \
  https://repo1.maven.org/maven2/com/epam/parso/2.0.14/parso-2.0.14.jar \
  --output "$artifacts/parso-2.0.14.jar"
echo "3b7e7a32915e04caed5dba31be1430aa57b4f9fa2b3d0ab0ed29067510d16575  $artifacts/parso-2.0.14.jar" | shasum -a 256 -c -

curl --fail --location --silent --show-error \
  https://repo1.maven.org/maven2/org/scala-sbt/sbt-launch/1.9.8/sbt-launch-1.9.8.jar \
  --output "$artifacts/sbt-launch-1.9.8.jar"
echo "75c61f9717043ce4fefb0c85340c1b5cc4404f291358e76a28fc6e330af6dd92  $artifacts/sbt-launch-1.9.8.jar" | shasum -a 256 -c -

(cd "$repo" && java -Dspark.version=3.5.8 -jar "$artifacts/sbt-launch-1.9.8.jar" '++2.12.18!' clean package)
cp "$repo/target/scala-2.12/spark-sas7bdat-3.0.0-s_2.12.jar" "$artifacts/"
echo "fd0c763c2b92457a583aab8855fd81fb76d30b9d017dcc39d17d952fe2ff3a27  $artifacts/spark-sas7bdat-3.0.0-s_2.12.jar" | shasum -a 256 -c -
printf '%s\n' '{"artifact_sha256":"fd0c763c2b92457a583aab8855fd81fb76d30b9d017dcc39d17d952fe2ff3a27","build_command":"java -Dspark.version=3.5.8 -jar sbt-launch-1.9.8.jar ++2.12.18! clean package","build_tool":"sbt","build_tool_launcher_sha256":"75c61f9717043ce4fefb0c85340c1b5cc4404f291358e76a28fc6e330af6dd92","build_tool_version":"1.9.8","scala_version":"2.12.18","schema_version":"1.0","spark_sas7bdat_revision":"dad0840bd89b7581c35a41ce372c61dc42d15eab","spark_version":"3.5.8"}' > "$artifacts/scale01-build-receipt.json"
echo "e919e2e2efe2f4ff44c8b68e401f29e97b95f9d4b3bd32926723eac954dc92c6  $artifacts/scale01-build-receipt.json" | shasum -a 256 -c -

target="${SMF_SCALE01_PYTEST_TARGET:-tests/integration/test_scale01_distributed_reader.py}"
SMF_REQUIRE_SCALE01=1 SMF_SCALE01_ARTIFACT_ROOT="$artifacts" \
  python -m pytest -q "$target"
