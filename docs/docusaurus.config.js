// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import { themes as prismThemes } from 'prism-react-renderer';
import path from 'path';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Commit Boost',
  tagline: 'Commit-Boost allows Ethereum validators to safely run MEV-Boost and community-built commitment protocols',
  favicon: 'img/favicon.ico',

  // Set the production url of your site here
  url: 'https://commit-boost.github.io',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/commit-boost-client/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'Commit-Boost', // Usually your GitHub org/user name.
  projectName: 'commit-boost-client', // Usually your repo name.

  onBrokenLinks: 'ignore',
  onBrokenMarkdownLinks: 'warn',

  customFields: {
    latestVersion: '0.9.6',
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/docs',
          sidebarPath: './sidebars.js',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/Commit-Boost/commit-boost-client/tree/main/docs/',

          versions: {
              '0.10.0-rc2': { label: 'v0.10.0-rc2 (pre-release)', path: '0.10.0-rc2', banner: 'unreleased' },
              '0.9.6': { label: 'v0.9.6 (stable)', path: '0.9.6' },
            },
            // Default version is the latest published release
            // (Docusaurus picks this automatically based on versions.json order)
            lastVersion: '0.9.6',
            includeCurrentVersion: false,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      // Replace with your project's social card
      image: 'img/icon.png',
      navbar: {
        title: 'Commit Boost',
        logo: {
          alt: 'Commit Boost Icon',
          src: 'img/icon.png',
        },
        items: [
          // { to: '/', label: 'Docs', position: 'left' },
          // { to: '/api', label: 'API', position: 'left' },
          { type: 'docsVersion', label: 'Docs', position: 'left' },
          { type: 'docsVersionDropdown', position: 'right' },
          { to: '/api', label: 'API', position: 'left' },
          {
            href: 'https://github.com/Commit-Boost/commit-boost-client',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          // {
          //   title: 'Docs',
          //   items: [
          //     {
          //       label: 'Tutorial',
          //       to: '/docs/intro',
          //     },
          //   ],
          // },
          {
            title: 'Links',
            items: [
              {
                label: 'Github',
                href: 'https://github.com/Commit-Boost/commit-boost-client',
              },
              {
                label: 'X (Twitter)',
                href: 'https://x.com/Commit_Boost',
              },
            ],
          },
        ],
        // copyright: `Copyright © ${new Date().getFullYear()} My Project, Inc. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash','toml'],
      },
    }),

  plugins: [
    function webpackAliasPlugin() {
      return {
        name: 'webpack-alias-plugin',
        configureWebpack() {
          return {
            resolve: {
              alias: {
                '@signer-api-spec': path.resolve(__dirname, '..', 'api', 'signer-api.yml'),
              },
            },
          };
        },
      };
    },
  ],
};

export default config;
