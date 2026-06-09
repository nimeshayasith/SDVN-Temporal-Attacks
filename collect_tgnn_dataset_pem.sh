#!/bin/bash
# collect_tgnn_dataset_pem.sh
NS3=/home/sdvn_echo_topology/ns-allinone-3.35/ns-3.35
DATASET=$NS3/results/tgnn_dataset
mkdir -p $DATASET

# Normal traffic — all 3 mobility scenarios, all speeds
for SCENARIO in 0 1 2; do
  if   [ $SCENARIO -eq 0 ]; then SPEEDS="0 10 20 30 40 50 60"; NAME="urban"
  elif [ $SCENARIO -eq 1 ]; then SPEEDS="0 10 20 30 40 50 60 70 80 90 100"; NAME="rural"
  else                            SPEEDS="0 10 30 50 70 90 110 130 150 170 190 210 230 250"; NAME="autobahn"
  fi
  for SPEED in $SPEEDS; do
    echo "=== Normal: $NAME speed=$SPEED ==="
    cd $NS3 && ./waf --run "scratch/routing --simTime=60 --N_Vehicles=22 \
      --N_RSUs=7 --attack_scenario=0 --routing_algorithm=4 \
      --maxspeed=$SPEED --mobility_scenario=$SCENARIO" 2>/dev/null
    SRC=$NS3/PEM_EVENT_LOG/00_Baseline_No_Attack.csv
    [ -f "$SRC" ] && cp "$SRC" $DATASET/normal_${NAME}_${SPEED}.csv && \
      echo "  Saved normal_${NAME}_${SPEED}.csv ($(wc -l < $DATASET/normal_${NAME}_${SPEED}.csv) rows)"
  done
done

# Attack traffic — all 12 scenarios at urban 30 km/h
for ATTACK in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if [ $ATTACK -le 4 ]; then ANAME="TTW"; elif [ $ATTACK -le 8 ]; then ANAME="BSHH"; else ANAME="ME"; fi
  RSU=0
  [ $ATTACK -eq 2 ] || [ $ATTACK -eq 4 ] || [ $ATTACK -eq 6 ] || \
  [ $ATTACK -eq 8 ] || [ $ATTACK -eq 10 ] || [ $ATTACK -eq 12 ] && RSU=7
  echo "=== Attack $ATTACK ($ANAME) ==="
  cd $NS3 && ./waf --run "scratch/routing --simTime=60 --N_Vehicles=22 \
    --N_RSUs=$RSU --attack_scenario=$ATTACK --routing_algorithm=4 \
    --maxspeed=30 --mobility_scenario=0" 2>/dev/null
  # Find the event log for this scenario
  LOGFILE=$(ls $NS3/PEM_EVENT_LOG/0${ATTACK}_*.csv 2>/dev/null || ls $NS3/PEM_EVENT_LOG/${ATTACK}_*.csv 2>/dev/null | head -1)
  [ -f "$LOGFILE" ] && cp "$LOGFILE" $DATASET/attack_${ANAME}_s${ATTACK}_urban_30.csv && \
    echo "  Saved attack_${ANAME}_s${ATTACK}_urban_30.csv ($(wc -l < $DATASET/attack_${ANAME}_s${ATTACK}_urban_30.csv) rows)"
done

echo ""
echo "=== Dataset complete ==="
ls -lh $DATASET/
wc -l $DATASET/*.csv | tail -1
