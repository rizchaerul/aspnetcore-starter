INSERT INTO [Account]
(
    [Id],
    [Code],
    [FullName],
    [Email],
    [Password]
)
VALUES
(
    NEWID(),
    '2201794416',
    'Chaerul Rizky',
    'riz.chaerul@gmail.com',
    -- P@ssw0rd
    '$2a$12$ge98sd8nQBL7gaM3mLDCsu5tqJoB5zuYYWUxnDwAbeclkbTJ2ZoS2'
);
