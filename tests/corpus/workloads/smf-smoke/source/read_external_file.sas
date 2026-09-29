/* SMF-owned bootstrap fixture. This exists only to prove corpus plumbing. */
data work.member_sample;
    infile "members.csv" dsd firstobs=2;
    length member_id $12 plan $8;
    input member_id $ plan $ allowed_amount;
run;

proc sql;
    create table work.member_summary as
    select plan, count(*) as member_count, sum(allowed_amount) as total_allowed
    from work.member_sample
    group by plan;
quit;
