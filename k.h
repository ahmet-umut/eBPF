//kernel.header
//Have to change this file and recompile eBPF programs RK and SKI for trying exoerşnebt parameters
#define fs 1      //file size
#define pds 1     //packet data size
#define pcif (fs/pds)   //packet count in files
#define re 2      //repetption of experiment
#define acc 1     //ack cumulativity      (max. number of acks inside a ack packet)