import React from 'react';
import Head from '@docusaurus/Head';
import Layout from '@theme/Layout';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

export default function Home() {
    const { siteConfig } = useDocusaurusContext();
    const baseUrl = siteConfig.baseUrl || '/';
    const latestVersion = siteConfig.customFields?.latestVersion || '0.10.0-rc2';
    const target = `${baseUrl}docs/${latestVersion}/`;

    return (
        <Layout title="Redirecting...">
            <Head>
                <meta httpEquiv="refresh" content={`0;url=${target}`} />
                <link rel="canonical" href={target} />
            </Head>
            <p style={{padding: '2rem', textAlign: 'center'}}>
                Redirecting to <a href={target}>latest docs</a>...
            </p>
        </Layout>
    );
}
