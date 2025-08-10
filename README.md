# netunnel

A network tunnel (`netunnel`) is a facility to build security communication between two endpoints over the unsecure network. Now available tunnel type are:

- TCP: use tcp connections to handle application connections directly
- SSH: use a secure shell connection as the low-level tunnel, and use a custom channel to handle application connections
