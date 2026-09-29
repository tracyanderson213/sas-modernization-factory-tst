#!/bin/bash
set -e
sas -sysin jobs/extract_claims.sas
sas -sysin jobs/transform_claims.sas
sas -sysin jobs/publish_claims.sas
