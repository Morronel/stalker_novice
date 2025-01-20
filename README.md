# STALKER: Novice's Web Challenge
Difficulty: "Novice"

A FREE and OPEN SOURCE web-based CTF (Capture The Flag) challenge inspired by the S.T.A.L.K.E.R. game series atmosphere. This project is a fan creation and is not affiliated with or endorsed by GSC Game World or the official S.T.A.L.K.E.R. team.

## Description
Welcome to the Zone, stalker! This web challenge will test your basic web security skills in a S.T.A.L.K.E.R.-themed environment. As a rookie stalker, you've just arrived at the Cordon. Sidorovich, the local trader, has a special task for you - find hidden flags across different locations and exchange them for valuable equipment.

## Features
- 9 unique locations with different web security challenges
- Dual language support (English/Ukrainian)
- Atmospheric S.T.A.L.K.E.R. interface
- Progressive difficulty curve
- Various web security concepts
  - SQL
  - XSS
  - Cookie manipulation
  - Traffic analysis
  - Cryptography basics
  - Header inspection
  - Request parameter tampering

## Installation

### Prerequisites
- Docker
- Docker Compose

### Quick Start
1. Clone the repository:
```bash
git clone https://github.com/Morronel/stalker_novice.git
cd stalker-novice
```

2. Build and run the container:
```bash
sudo docker compose up
```

3. Access the challenge at:
```
http://127.0.0.1:5000
```

Each location contains a flag in the format `STALKER{flag_text}`. Exchange these flags with Sidorovich for equipment!

## Development
The project is built with:
- Flask (Python web framework)
- Flask-Babel (internationalization)
- SQLite (database)
- Docker (containerization)

## License
This project is released under the MIT License. See the LICENSE file for details.

## Disclaimer
This is a fan-made CTF challenge inspired by the S.T.A.L.K.E.R. series. All S.T.A.L.K.E.R.-related trademarks and copyrights are property of their respective owners. This project is created for educational purposes only.

## Contributing
Feel free to submit issues, fork the repository, and create pull requests for any improvements. Thanks to Bogdan Shchogolev for testing the challenge and providing feedback.

## Known Issues
- Flags auto-submit after encountering them in the challenge.

Good hunting, stalker! 

## Screenshots
![image](https://github.com/user-attachments/assets/b61d8b93-3593-421f-b28a-6ab1da9bce00)
![image](https://github.com/user-attachments/assets/85ff34dc-db82-4976-8d8d-ace6ac7c0de2)
![image](https://github.com/user-attachments/assets/dffb5484-3398-4436-932a-fa357f377f96)

