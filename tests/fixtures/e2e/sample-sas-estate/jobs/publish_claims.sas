libname curated "/data/curated";

data _null_;
    set curated.claims;
    file "output/claims_report.csv";
    put member_id ',' claim_id ',' paid_amount;
run;
