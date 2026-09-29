/* SMF-authored semantic fixture: PROC SQL reads, join, filter, aggregation, and output. */
%macro seed_members(dataset=);
data &dataset;
    input member_id $ region $ status $;
datalines;
M001 EAST ACTIVE
M002 WEST INACTIVE
M003 NORTH ACTIVE
;
run;
%mend;

%macro seed_claims(dataset=);
data &dataset;
    input member_id $ paid_amount;
datalines;
M001 10
M001 20
M002 100
M003 5
M003 7
;
run;
%mend;

%seed_members(dataset=work.members);
%seed_claims(dataset=work.claims);

proc sql;
    create table work.active_member_cost as
    select m.member_id,
           m.region,
           sum(c.paid_amount) as total_paid
    from work.members as m
    inner join work.claims as c
        on m.member_id = c.member_id
    where m.status = 'ACTIVE'
    group by m.member_id, m.region;
quit;
