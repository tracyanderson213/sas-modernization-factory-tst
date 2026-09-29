libname raw "/data/raw";
libname src odbc dsn=claims_dw schema=claims user=svc_claims password="DO_NOT_EXPOSE";

%include "macros/common_macros.sas";

data raw.claims_stage;
    set src.claims;
run;
