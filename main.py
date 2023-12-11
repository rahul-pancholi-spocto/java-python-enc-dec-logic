from RsaAesClient import RsaAesClient


rsa_aes_client = RsaAesClient()
rsa_aes_client.decryptFile('uat_spocto_sma_collection_report_encrypted.csv', 'uat_spocto_sma_collection_report_aes.txt')