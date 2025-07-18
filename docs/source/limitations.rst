Limitations
===========

- Omnia supports adding up to 1000 nodes when discovered via BMC. 
- Dell Technologies provides support only for the Dell-developed modules of Omnia. Third-party tools deployed by Omnia are not covered under Dell support.
- In a single node cluster, the login node and Slurm functionalities are not applicable.
- Containerized benchmark job execution is not supported on Slurm clusters.
- Only one storage instance (PowerVault) is currently supported in the HPC cluster.
- All iDRACs must use the same username and password.
- The IP subnet 10.4.0.0 is reserved for Nerdctl and cannot be used for any networks in the Omnia cluster.
- Omnia playbooks will fail if the OIM is unable to access online resources or the Internet.