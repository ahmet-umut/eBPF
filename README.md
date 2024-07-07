**Creating namespaces:**
```
alias e="sudo ip netns exec"
sudo ip netns add n1
sudo ip netns add n2
sudo ip link add ven1 type veth peer name ven2
sudo ip link set ven1 netns n1
sudo ip link set ven2 netns n2
sudo ip netns exec n1 ip link set ven1 up
sudo ip netns exec n2 ip link set ven2 up
sudo ip netns exec n1 ip addr add 10.0.0.1/24 dev ven1
sudo ip netns exec n2 ip addr add 10.0.0.2/24 dev ven2
```
