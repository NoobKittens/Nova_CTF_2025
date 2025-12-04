# Fly Challenge Writeup

## Challenge Information
- **Category**: OSINT
- **Points**: 20


![](attachments/Pasted%20image%2020251130180025.png)


![](airplane.jpg)



The plane in your picture uses the “special livery” of Leicester City Football Club / King Power on a Thai AirAsia A320. This corresponds to the aircraft with registration HS‑ABV. 


I looked up HS-ABV’s flight history on a site that tracks tail-registration flights. That revealed a list of sectors flown by HS-ABV (with dates and flight numbers). 


```
https://it.flightera.net/en/planes/HS-ABV/2025-05-18%2002_30
```


![](attachments/Pasted%20image%2020251130181655.png)


Since the plane in the image is HS-ABV, and HS-ABV flew FD608 on 17 May.

Therefore origin = DMK, destination = PNH, flight = FD608 → giving the flag 

Nova_ctf{DMK,PNH,FD608}.


