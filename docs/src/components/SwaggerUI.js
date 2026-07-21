import React from 'react';
import SwaggerUI from 'swagger-ui-react';
import 'swagger-ui-react/swagger-ui.css';

function getSpecUrl() {
    if (typeof window === 'undefined') return null;

    // localhost dev: webpack bundles the spec via raw-loader
    if (window.location.hostname === 'localhost') return null;

    // Production GitHub Pages: derive org/repo/branch from the current URL
    // e.g. https://commit-boost.github.io/commit-boost-client/ → Commit-Boost/commit-boost-client/main
    const host = window.location.hostname; // e.g. commit-boost.github.io
    const org = host.replace('.github.io', ''); // e.g. commit-boost → Commit-Boost
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const repo = pathParts[0] || 'commit-boost-client';
    const branch = window.location.searchParams?.get('branch') || 'main';

    return `https://raw.githubusercontent.com/${org}/${repo}/${branch}/api/signer-api.yml`;
}

const SwaggerUIComponent = () => {
    const specUrl = getSpecUrl();
    if (!specUrl) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const localSpec = require('!!raw-loader!@signer-api-spec').default;
        return <SwaggerUI spec={localSpec} />;
    }
    return <SwaggerUI url={specUrl} />;
};

export default SwaggerUIComponent;
