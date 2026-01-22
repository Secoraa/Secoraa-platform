# Secoraa Frontend (React + Webpack)

Modern React frontend for Secoraa ASM platform, built with Webpack.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start development server:
```bash
npm run dev
```

The app will run on `http://localhost:8501`

## Environment Variables

Create a `.env` file:
```
REACT_APP_API_URL=http://localhost:8000
```

Note: In Webpack, environment variables must be prefixed with `REACT_APP_` to be accessible in the code.

## Build

```bash
npm run build
```

The production build will be in the `dist/` directory.

## Features

- Dark theme matching Secoraa design
- Asset Discovery with domain management
- Scan management and history
- Responsive design
- Fast API integration
- Webpack for bundling

## Project Structure

```
frontend-react/
├── public/          # Static assets
│   ├── images/      # Logo and images
│   └── index.html   # HTML template
├── src/             # Source code
│   ├── api/         # API client
│   ├── components/  # React components
│   ├── pages/       # Page components
│   └── styles/      # CSS files
├── webpack.config.js # Webpack configuration
└── package.json     # Dependencies

```
