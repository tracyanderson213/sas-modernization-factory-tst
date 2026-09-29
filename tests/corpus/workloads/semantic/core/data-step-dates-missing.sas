/* SMF-authored semantic fixture: DATA step, informats, formats, and missing values. */
data work.member_dates;
    input member_id $ birth_date :mmddyy10. score status $;
    age_days = '31DEC2025'd - birth_date;
    if missing(score) then score_status = 'MISSING';
    else if score >= 80 then score_status = 'HIGH';
    else score_status = 'NORMAL';
    format birth_date date9.;
datalines;
M001 01/15/1980 92 A
M002 12/03/1975 . A
M003 07/20/1991 74 I
;
run;
