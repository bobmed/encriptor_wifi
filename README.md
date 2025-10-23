# encriptor_wifi
ESP-12 project that allows you to decrypt a file with an HTML page encrypted using the AES-256 standard and display it

## Algorithm of actions
* Connect to ESP-12 via Wi-Fi (the password and name are configured in the code)
* Load the start page by following the link http://hello.there
* Upload the encrypted file using the appropriate fields on the page
* Wait for the file to be decrypted in parts and downloaded to your device
* View the decrypted page
