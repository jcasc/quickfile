package main

const TLS_CERT = `
Ci0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlFcERDQ0Fvd0NDUUNlVDJj
Sk9XL1dyakFOQmdrcWhraUc5dzBCQVFzRkFEQVVNUkl3RUFZRFZRUUtEQWx4CmRX
bGphMlpwYkdVd0hoY05Nak13TmpJeU1USXpNekl4V2hjTk1qUXdOakl4TVRJek16
SXhXakFVTVJJd0VBWUQKVlFRS0RBbHhkV2xqYTJacGJHVXdnZ0lpTUEwR0NTcUdT
SWIzRFFFQkFRVUFBNElDRHdBd2dnSUtBb0lDQVFDNgovTnRnd1ZISWROOVdTSVBn
OG0yZStVY2dlRWpNaGZEK3JSeWZRRlFKaStNQzhRL1ZWblMzYjMyUGtHMnVWTkZV
Ckw4MGRrQmdLTlFJZEVLNERUY3FMOVc1aGZ4bGsxaHFINGRTZkxGQm9JLy93TTQw
eGd4QkRUbDNiQ1lVR1BhWEIKbVJ1dEVFNm9WUWJHMHQySDlJUFZYVVJLdG5KMjFs
blFvWnpBV2FaT0FuZGJrR0tIeWR0bHBPdm8yZVdlUHVKKwpmcnFiZWhKaUN4amNN
dDBDcXJBaUZ2SW1IYllaYmdFWnJuVER5RlpHakJNZ1gxeXNDVXhndjNHZDRkeUx2
MW1rCk1YdFNuMk5ITHl1NzRJTzc3b0JyWVRIUkQwb2tXS3ZLMTZjcUVNdDl0eTFt
TENmZmFKc1ZQN1ZKVllKdlNzZXMKSlZHWjFZZkpjT2N6R3pUZG12eDNwbU9WN1Vp
WTFDSk5LV2hPU3hEOUdzckVFMUh5MGRxUjFiQXc0Q1NTY3piVgpDcWszWjVZRXFM
Ky9UUDhHdnA3bk9GcWljRkZlNG5MdGJWc0hyNllTVnM2NThEd25sUDhxVXBWMTNF
eFdsSTFZClNFUHYwbDkzM085TEVGSWxwMDZyTS84dFJiZ2cxTU9XTnN0dHkrS2pi
OGd0d2lnc0c3eU43VjNaNnBNbkJIR1kKY3pMZUxZYkhhZkxMaE05QXFIUlRTNXo5
bS9rRW9UdWJ6L3Q3UzU0OXAxV3dYQUh1aTRHeG42Tks4NG5SaStvWApGMmdqN3pR
RktodHA3MXJzV05MRXdRclpTc1BTdS9NY3UveTkwUmQvRUIrUlpIdFNmRWhyMHRC
QjQ2SWpxdTNyCkxTM2hRU1ZockJ1dE5RZ3JOU3hmMnZtWWY1SVBSZ1JZQ3FiUTF4
TXVJUUlEQVFBQk1BMEdDU3FHU0liM0RRRUIKQ3dVQUE0SUNBUUFUOGcvU1B3aVVt
MzcvTUdsSkRwWE5xWVFyNmZsN0F2UnJIR1pHbW5NNXMyZHAvalNDVXZocQpTMXBY
dDlMWXJQdUtZMGFyK0ZidzJ5SG1ZeE9Qc3k2eTFOaU1lNHdrLzJkNzlzOHZwWTZP
S3dqODNScDZhdG94CjRFb3NCRFgyczN0NGx5dlJmODNZUkdtbnZyTlZMb1d5VU5N
cHBCRlpmUDYxT3UzdWNGU21XU2gyS1JraEdIcWgKUCtiZGpyc0JKN21DekJvbUlC
V3Z1R1lzU0R4cW9ZeEVlVldhbUltU0JTTStKanVVUGthUVE0dGJYcGRRWTFYMQph
RjRqbkJBdUpTZldzRWlPQVFhRVlsUUowUUlYMWRDMm9JbHpTZDRCTnJJOXU0VE14
M1JZc2JqbUJjQlAwZnRtClhDWSswTUxpcjFmbUY3MmVEaDNDUnJvem1ySEhaZ1Bw
SDlQRmwwWnM4WW5aeTByTFRBNG10SEFzWkVGTS9VbTYKQUgvZXhvYUhrQVBVZU13
bTJVL09KQkVZK0RGbUpvODJDUVN4UFpUeHZmZU9uck9wcTg4WGVMTS9YVVdQaGRt
TgpGaG9qNnpBVitQS0lDU1NRODMzbzV0QmJGSWFpZXFmYktldHBveGNDazdZcTdh
b082RGJROFN2Q0xjTklwMGJkCi9INUgwZCtoZjBSMFZLelpER21OUkE2SEx5OFlM
VUw5a2NxTW1XMGpmd3l5TXZBNnJTOWRjODhMRTk0eWNXTHAKKzVVZEN4b3pPYm8x
dDkrbDNaYmNHR0YxRkp4YVlWK0tDTitudnIyUmY0ZU5PMFljY1N0YStuM1FKNVpM
ZWY0bQorWFY4c3gwVlVRZTJxdHV1WmxtbXlPMlV4UzV1K0tscFVMeWRZTWowMGxF
TndJVDllcVE5dUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==`

const TLS_KEY = `
Ci0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLQpNSUlKUXdJQkFEQU5CZ2txaGtp
Rzl3MEJBUUVGQUFTQ0NTMHdnZ2twQWdFQUFvSUNBUUM2L050Z3dWSElkTjlXClNJ
UGc4bTJlK1VjZ2VFak1oZkQrclJ5ZlFGUUppK01DOFEvVlZuUzNiMzJQa0cydVZO
RlVMODBka0JnS05RSWQKRUs0RFRjcUw5VzVoZnhsazFocUg0ZFNmTEZCb0kvL3dN
NDB4Z3hCRFRsM2JDWVVHUGFYQm1SdXRFRTZvVlFiRwowdDJIOUlQVlhVUkt0bkoy
MWxuUW9aekFXYVpPQW5kYmtHS0h5ZHRscE92bzJlV2VQdUorZnJxYmVoSmlDeGpj
Ck10MENxckFpRnZJbUhiWVpiZ0Vacm5URHlGWkdqQk1nWDF5c0NVeGd2M0dkNGR5
THYxbWtNWHRTbjJOSEx5dTcKNElPNzdvQnJZVEhSRDBva1dLdksxNmNxRU10OXR5
MW1MQ2ZmYUpzVlA3VkpWWUp2U3Nlc0pWR1oxWWZKY09jegpHelRkbXZ4M3BtT1Y3
VWlZMUNKTktXaE9TeEQ5R3NyRUUxSHkwZHFSMWJBdzRDU1NjemJWQ3FrM1o1WUVx
TCsvClRQOEd2cDduT0ZxaWNGRmU0bkx0YlZzSHI2WVNWczY1OER3bmxQOHFVcFYx
M0V4V2xJMVlTRVB2MGw5MzNPOUwKRUZJbHAwNnJNLzh0UmJnZzFNT1dOc3R0eStL
amI4Z3R3aWdzRzd5TjdWM1o2cE1uQkhHWWN6TGVMWWJIYWZMTApoTTlBcUhSVFM1
ejltL2tFb1R1YnovdDdTNTQ5cDFXd1hBSHVpNEd4bjZOSzg0blJpK29YRjJnajd6
UUZLaHRwCjcxcnNXTkxFd1FyWlNzUFN1L01jdS95OTBSZC9FQitSWkh0U2ZFaHIw
dEJCNDZJanF1M3JMUzNoUVNWaHJCdXQKTlFnck5TeGYydm1ZZjVJUFJnUllDcWJR
MXhNdUlRSURBUUFCQW9JQ0FRQ25RNGo2QS9Ra1hHZHJ4M0l3eHF0SQppYlFXVjRM
SGNRa2l4N2ZTdkxodjBiSS83Mk02Y3h2MCtzWldwZHQzRm1ncDVwaVUyVkNuME1N
VFBOaHNIQ29UCkNIaTB2Zno1Tm95RkFINHg1SElJdGlzN3N1R2FhS01qa2ZaaStT
RUZkQi9TRGlPenErS3dzVjVlZkVHdVhBdVIKME54RitPNXJYMUw0VFpqcWQwZE1n
T2hELytRamsyMnVmdGlJY21IMExFeHUydTRTSmlCTGs2R3BWOVpiakZRQwpLb1J4
bENKUW5SWmU0cStRY3FTNmRwS2xZcWlETzg0V3ZTbmxFU1UzM1BOUzdQQmorQy9X
ZlZ1aHREUWk2RFgzCjEvbTRDUFZKamdnZWFzb2QxdWd3aktzUHVtL3dhS0pSWDZ2
SzdiSy8yeVRCMktBbCs5eDdWWU43TTlzV1lJMTAKOEtkQXpsbG50TDYxSVRHU3d3
SGh5UkE3S29OZXFwOWZ3bGVwTXdUUHRPSnZzL2Y5UWNlblNEaTRldFZnNm84QQpq
RHpCYkhCTnBhbU9tbHJ4UW1hN01yS0ltTGZ6dEE5aUJyU3FJZjdpU0hIUTRBQ1Zs
LzNYTkRtb0tUak82enJ0CjY0Qm5raU1YcDI5WnN2OTZTVUJDaGcvTm14Z0pCczIr
YVVmcEJqaGQ1RGtkdU9VVm5WQXlsU1doVDZWclJheWMKcWgvd0hUQTY1M2ZRbXpH
elI4M0cxNGRtUGpBbjdNNkVRandlUWVpNXVyb2IwQ2tsald3VmlZYnlWcXE0VE53
TApsSzhOdzFzcHNaRXBEb3JNRStoQXhhejcweVhTNUJrbDgwbE9WeFQyMmZxNU1y
V0RzQlM3WmVJL2dxU21TOGVICnJmM2IveEJ1NlRJZ1c5bFVUVkxVQVFLQ0FRRUE4
OWJDRjdRdlZ4QWtDT0Z2dDhpY2ZMdFlzUnJ6MzNIUGtTa2oKc3kwNU9qUFFqTVh5
a0t1Q0VkTEpsVUg5VkNQd2UrclFQaC9STHhwWTlCUnhLNjZPT3M3OUljNXAyMnVt
YWVLSAp1YUsrTWxra3NjMkxWd0dzbUFXcWhFVlBpQW5BUUNpM1NlY3lPYWhpRzd5
cFNWS09hNy92YktXM0R3NnA2U3gwCnhWbkhUcmhaazV3OG9DMGh2RFZabmpQVXBM
M25ja21Kc21WVDUrMkIxMXMzcEs3bllzOVl5RFpsdzR5K1VSTmIKMCtyNVV5bkYw
MUJPUGhuOUIwL25ya1JCK05WZTY4Nk1NNUxUYitOL1JvS0xCeGZmRFVjZXVUV0hS
YVR5bDB2dgpwQ0x0SVFDajIwN3BkVnFwSGtPQmV0ckZwdllSUkw5U1g3OWpyMUcy
OGZrOVdoTWJid0tDQVFFQXhGQStvN2Z5CjdjKzk4czJoSS9ZTkFaMWY4clhXZ0dR
OTdhWGlGdmRXTFE0SmJLcVpqRVpIUlhWWFR5ZGxYU0s5bXFISm9jUk4KNGxZZHJl
cFBab1JoNXZweXNqTC9OYVpzVmllSnRGNnRUL05BcFRMT0JEbUpHQjl4S2M5aTBo
ZEEzUDkxNXhhZQpXYTJrM1M3OU5Kemk5a0lDVnI0YmU0Z2pmeUtBd0hlS0VMdDVF
TU9RTnRPMWNoc2NiWkNMYURnNlNFcjBORlhTCktGQ212bndtRGxZZXhMMzNzVkph
MGc5SlQvVTk4Y0dFeUhSN0pIMmI0YWRMUVdtMTAvZE1nZjgvVlByQTJsM0wKMFdT
OUxrT1ZsdWZIZndNemdjTmtVcXhmZDJYWjdwTCt0OUxza2puVzd1WXkvUEpITy9u
TFdrOFlhZ3ZXV092bQozWXBYMEFxMStYbkhid0tDQVFBV3EzZStGbTEwVGJiYjhJ
R2ZkNUk4OG5vTGRUTUpLaDZmSTFFRFhvZjhoa2EwClg4N3VibE9ZYnAxNU4vcGlj
VGp4ZkdKQjlGbFJaTVN5WkpnazlJU2FxUlhWcDhnbHN6dDBpckFOclRpN201Z1MK
dzhaWm4zazVaUVYyYUs4OU9aTGJKQzN1UEFWcVlPSkdLK01kUXdTa3RlSi9tbVNM
ak5SMUxrSG8rekRSZThndwpOZzFZNHZsSTh6alN3WVRha0NGTmVkTEllQzAxMmRv
QmVLU1N0Z1FqSnAzZGQxazh0Z0FYcjVJUkFMNlBZY25YCm5KYTVwVmJsOENMZEM5
R0tYZVFHVGx5d2lzMEhrUUlMUHlYSDBndFZ3Ni95aml4MmFDQjV1b0NjSlBjZzQx
dFkKajF5YklZT3BvYU1QRmZuY1RQSk1EdkdNbjFHWVFpT2RHWXYvck5rWEFvSUJB
SG5UU213VEZXQmJFUWVDY0VOKwp4K2Qrb0RKZ2diSy9nbWJlRUlZc0M0QitPMzhD
QjdPelVUdGJiRWtrcTVTMm9HODdnNE10N1I5T1RiREZ2V3hqCkx0WkdDYk5vVGxR
ZTZSQTJEUkN2eUdIYkZQenZvRVdpNXQ3ZmREeDhCRmxZTU5wMGRkaG9ndkFvQUMx
Nm9ZdHEKNkxYbGxNbjd3OVpQVDZmdjQzS05QRkxSNUhsd3d5Z2pEWEM0UGxZSDQx
dFR1V2R2akVpR0Vac1BJY3NJQkIzVgpkOWFrQlBnM29VREdWN3FVK0ZIMHc5QVo2
T2xtUWJ3eE0xUnVvM1hjKzgrWWROYnBuWkJsc0x4TEJkT1dBVmphCmtVVFMyYjNu
WVhTa244SGFwUG1Xb3hlMGZ6Ym5TZWlMVm96K1ZSSjFHNnI1ZHE4b2xXWXRUdUdn
bm9udWU2dEwKMVdVQ2dnRUJBTEVWdWdJQ1cvblBIZFIyZ1ZLUXV5QkVyZFpPQm1S
ZndLNGdqTEVHc0hTaXU4WlVKODRGeC83ZwpLdnIrYUlKNXpKbmQwWElWSm1IQk9J
Sk1zYUR3bW9uUWtDYTRTWVl4ZXRRWDhSdzcvY0I3a3YvU1lFWnRvcWVtCmgyN1pC
OTRDbGtYaHdaSU1ZdzdlTWkxOXJFVDZBUHVOeFAzTmtyNnhPalZlRW1VQkw3RnFB
VjlVUUxhQUZNdXUKZHUyb0M5VDNxZFloZGpzWkFiWGkwbm9GelFVd093c0l5YjVQ
VmlhZzJLY2FPWXBGa29Bbjh0aG5FU0ZPbGdneQo3Z2o3WURGTEIvZm1aNGRLQnMr
Z1NoUTk1V2NhSXhiSk1wWVBhVG9oSGRDSER5NCtLUlBGVXUxUEFCNHM5M3pSCm5U
MlZaZ1pyNHYwU1dQRHY0VVRDaFJGRWJyYml2UTg9Ci0tLS0tRU5EIFBSSVZBVEUg
S0VZLS0tLS0=`
