%include "shared/model_macros.sas";

proc logistic data=work.training;
    model outcome(event='1') = age risk_score prior_utilization;
run;
