libname raw "/data/raw";
libname curated "/data/curated";

data curated.claims;
    set raw.claims_stage;
run;
