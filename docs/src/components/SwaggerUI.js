import React from 'react';
import SwaggerUI from 'swagger-ui-react';
import 'swagger-ui-react/swagger-ui.css';
// eslint-disable-next-line import/no-webpack-loader-syntax
import localSpec from '!!raw-loader!@signer-api-spec';

const IS_LOCALHOST = typeof window !== 'undefined' && window.location.hostname === 'localhost';

const PROD_URL = 'https://raw.githubusercontent.com/Commit-Boost/commit-boost-client/main/api/signer-api.yml';

const SwaggerUIComponent = () => {
    if (IS_LOCALHOST) {
        return <SwaggerUI spec={localSpec} />;
    }
    return <SwaggerUI url={PROD_URL} />;
};

export default SwaggerUIComponent;
