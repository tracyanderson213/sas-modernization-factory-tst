/* SMF-authored semantic fixture: sorted DATA step MERGE with BY-group matching. */
data work.members;
    input member_id $ region $;
datalines;
M001 EAST
M002 WEST
M003 EAST
;
run;

data work.claim_totals;
    input member_id $ paid_amount;
datalines;
M001 120.50
M003 75.25
M004 44.00
;
run;

proc sort data=work.members; by member_id; run;
proc sort data=work.claim_totals; by member_id; run;

data work.member_claims;
    merge work.members(in=in_member) work.claim_totals(in=in_claim);
    by member_id;
    if in_member and in_claim;
run;
