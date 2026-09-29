%macro summarize(source=, target=);
proc sql;
    create table &target. as
    select
        region,
        count(*) as member_count,
        sum(paid_amount) as total_paid
    from &source.
    group by region;
quit;
%mend;

%summarize(source=work.claims, target=work.claim_summary);
