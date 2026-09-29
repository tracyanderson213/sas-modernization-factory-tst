/* %macro phantom; %mend; %phantom; &phantom; */
title '%quoted_call; &quoted_variable';
%let protected=%nrstr(%hidden(&hidden));
%macro duplicate; %mend;
%macro DUPLICATE; %mend;
%duplicate;
%macro self; %self; %mend;
%macro left; %right; %mend;
%macro right; %left; %mend;
%&selected;
proc format; value duplicate 1='one'; run;
x = {{ duplicate() }};
