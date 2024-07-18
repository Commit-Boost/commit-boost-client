// src/pages/swagger.js
import React from 'react';
import Layout from '@theme/Layout';
import SwaggerUIComponent from '../components/SwaggerUI';

const SwaggerPage = () => {
    return (
        <Layout title="Signer API">
            <div style={{ padding: '20px' }}>
                <SwaggerUIComponent />
            </div>
        </Layout>
    );
};

export default SwaggerPage;
