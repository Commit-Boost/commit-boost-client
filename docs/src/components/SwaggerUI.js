import React from 'react';
import SwaggerUI from 'swagger-ui-react';
import 'swagger-ui-react/swagger-ui.css';

const SwaggerUIComponent = () => {
    return <SwaggerUI url="https://raw.githubusercontent.com/Commit-Boost/commit-boost-client/main/api/signer-api.yml" />;
};

export default SwaggerUIComponent;
