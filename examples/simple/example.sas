/* Synthetic example for factory development only. */

proc sql;
    create table work.customer_summary as
    select
        customer_id,
        count(*) as transaction_count,
        sum(amount) as total_amount
    from work.transactions
    where transaction_date >= '01JAN2026'd
    group by customer_id;
quit;
