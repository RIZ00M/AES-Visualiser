# AES-128 Visualiser

An interactive, step-by-step visualiser for AES-128 encryption. Enter a plaintext and a key, then walk through all 10 rounds and watch each byte of the state change.

No build step, no dependencies. Plain HTML, CSS and JavaScript.

## Features

- Text or hex input for plaintext and key (16 bytes each)
- 40 steps: load state, initial AddRoundKey, 9 full rounds, final round without MixColumns
- Highlights every byte a step changed; click any byte to inspect it
- **SubBytes**: 16×16 S-box with the looked-up entries marked
- **ShiftRows**: bytes tinted by their starting column
- **MixColumns**: the GF(2⁸) products for the selected column
- **AddRoundKey**: bit-level XOR of one byte
- **Key schedule**: all 11 round keys, with RotWord / SubWord / Rcon worked through
- Keyboard control (← / →), dark mode, responsive layout

## Run it

Open `index.html` in a browser, or serve the folder:

```bash
npm start
```

## Test it

The cipher core is checked against the FIPS-197 test vectors (Node 18+):

```bash
npm test
```

## Project structure

```
aes-visualiser/
├── index.html          Page markup
├── css/
│   └── style.css       Styles and light/dark theme tokens
├── js/
│   ├── aes.js          AES-128 core (pure functions, no DOM)
│   └── app.js          UI rendering and event handling
├── test/
│   └── aes.test.js     FIPS-197 test vectors
├── .github/workflows/
│   └── test.yml        CI: runs the tests on push and PR
├── package.json
├── LICENSE
└── README.md
```

`aes.js` builds the full list of steps (`buildSteps(plaintext, key)`); `app.js` only renders them. The S-box is computed from the GF(2⁸) inverse and affine transform rather than hard-coded.

## Deploy to GitHub Pages

1. Push this repo to GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, select `main` and `/ (root)`, then save.

The site will be live at `https://<your-username>.github.io/<repo-name>/`.

## Disclaimer

This is an educational tool. It is not constant-time and is not meant to protect real data. Use a vetted cryptography library for anything that matters.

## Licence

[MIT](LICENSE)
