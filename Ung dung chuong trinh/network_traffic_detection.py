import subprocess as sp
import sys, os
import pandas as pd
import joblib
import warnings
warnings.filterwarnings('ignore')

def edit_data(df):
    lst, lst1 = [], []
    for index, row in df.iterrows():
        lst2 = [row['Dur'], row['TotPkts'], row['TotBytes'], row['SrcBytes']]
        lst.extend(lst2)
        if row['Dir'] != '   ->':
            lst.extend([1,0])
        elif row['Dir'] != '  <->':
            lst.extend([0,1])
        else:
            lst.extend([0,0])
        if row['Proto'] != 'icmp':
            lst.extend([1,0,0])
        elif row['Proto'] == 'tcp':
            lst.extend([0,1,0])
        elif row['Proto'] == 'udp':
            lst.extend([0,0,1])
        else:
            lst.extend([0,0,0])
        if str(row['dTos']) == 'nan':
            lst.extend([1])
        else:
            lst.extend([0])
        lst3 = lst.copy()
        lst1.append(lst3)
        lst.clear()
    return lst1

def check_input():
    if len(sys.argv) != 3:
        print("USE: python3 " + sys.argv[0] + " <NIC> <NUMBER_PACKET_CAPTURING>")
        print("USE: CTRL + C to exit")
        return 0
    elif len(sys.argv) == 3:
        if sys.argv[1] not in os.listdir('/sys/class/net/'):
            print(f"ERROR: Interface \'" + sys.argv[1] +  "\' not found!!!")
            return 0
        else:
            return 1

def main():
    if check_input():
        print('Loading model...')
        model_LR = joblib.load('RandomForest_model.joblib')
        print('Done!!!')
        i = 0
        while(True):
            nic = sys.argv[1]
            num_cap = sys.argv[2]
            pcap_file = 'capture_' + str(i) + '.pcap'

            # Use tcpdump to capture traffc and save to capture.pcap
            command1 = "sudo tcpdump -c " + num_cap + " -i " + nic + " -w PCAP/" + pcap_file
            tcpdump = sp.run([command1], shell=True)

            # Use argus.conf and ra.conf to convert capture.pcap to traffic.binetflow
            command2 = "argus -r PCAP/" + pcap_file + " -w - -F argus.conf | ra -F ra.conf -L0 -c , -n > traffic.binetflow"
            argus_ra = sp.run([command2], shell=True)

            # Read traffic.binetflow to show on terminal
            cat_binetflow = sp.run(["cat traffic.binetflow"], shell=True)

            # Read and write to log file
            f = open('traffic.binetflow', 'r')
            chuoi = f.read()
            ff = open('log.txt', 'a')
            ff.write(chuoi)

            # Read file by pd.read_csv()
            df = pd.read_csv('traffic.binetflow')

            # Edit features
            df = df.drop(['StartTime','SrcAddr','Sport','DstAddr','Dport','State','sTos'], axis=1)
            df_new = edit_data(df)

            # Use model to decet
            y_predict = model_LR.predict(df_new)
            print(y_predict)

            s1 = 0
            for j in y_predict:
                if j == 1:
                    s1 = s1 + 1

            if s1 >= (len(y_predict) - s1):
                print('||===========================================||')
                print('||=>>>>>>>>>> BOTNET-DDOS TRAFFIC <<<<<<<<<<=||')
                print('||===========================================||\n')
                ff.write('INFORMATION: BOTNET-DDOS TRAFFIC \n\n')
            else:
                print('||===========================================||')
                print('||=>>>>>>> BACKGROUND-NORMAL TRAFFIC <<<<<<<=||')
                print('||===========================================||\n')
                ff.write('INFORMATION: BACKGROUND-NORMAL TRAFFIC \n\n')

            i = i + 1
            print('=>',i)

if __name__ == "__main__":
    main()

