CREATE TABLE our_db.automation.our_data_table (
    id INTEGER AUTOINCREMENT PRIMARY KEY,
    attack_vectors VARCHAR(255) NOT NULL,
    attack_chain VARCHAR(255) NOT NULL,
    attack_surfaces VARCHAR(255) NOT NULL,
    pressure_points VARCHAR(255) NOT NULL,
    vulnerability_categories VARCHAR(255) NOT NULL,
    remediation VARCHAR(255) NOT NULL,
    risk_level VARCHAR(255) NOT NULL,
    exploitation_methods VARCHAR(255) NOT NULL,
    vulnerable_points VARCHAR(255) NOT NULL
);
