
# ΦNET — Overlay Network
www.phinetproject.com
<table>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/24e41765-8d0d-449b-9f08-6260dd9dd573" alt="Screenshot_20260715_193958" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/e8ae7bee-74df-4a32-8607-c0c6f413dc84" alt="Screenshot_20260715_194031" width="100%"/></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/28d4abdd-7795-427b-91b3-2ee6eda4e4d2" alt="Screenshot_20260715_194047" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/ce1f362d-98e7-4b0c-a518-8ea4ae956ec2" alt="Screenshot_20260715_194356" width="100%"/></td>
  </tr>
  <tr>
    <td><img src="https://github.com/user-attachments/assets/5cb3a4bb-99a1-4c83-b56b-e94476b14f3c" alt="Screenshot_20260715_194131" width="100%"/></td>
    <td><img src="https://github.com/user-attachments/assets/b03817f6-cbe4-42ab-99e7-e89e17329440" alt="Screenshot_20260715_194147" width="100%"/></td>
  </tr>
</table>



A Tor-inspired overlay network

## Building

**Prerequisites:** Rust 1.80+, Node 18+, npm 9+

```bash
# Build everything
git clone https://github.com/PhiNetProject/phinet

cd phinet/

cargo build --release

cd phinet-browser

./sync-sidecar.sh /path/to/phinet/target/release/phinet-daemon

npm install

npm run tauri build
```
