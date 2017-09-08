// @flow
import * as jwtToken from "..";
import jsonWebToken from "jsonwebtoken";

const jwtKey = "secret";
const token = { foo: "bar" };


describe( "jwt-token", () => {

    describe( "sign", () => {

        it( "works", async () => {
            const result = await jwtToken.sign( token, jwtKey );
            expect( result ).toMatch( /^[^\s]+\.[^\s]+\.[^\s]+$/ );
            expect( jsonWebToken.decode( result ) ).toEqual( { ...token, "iat": expect.any( Number ) } );
        } );

        it( "adds exp", async () => {
            const result = await jwtToken.sign( token, jwtKey, { expiresIn: "30s" } );
            expect( jsonWebToken.decode( result ) ).toMatchObject( {
                "exp": expect.any( Number ),
            } );
        } );

        it( "throws exception if provided expiresIn is incorrect", async () => {
            expect.assertions( 1 );
            try {
                await jwtToken.sign( token, jwtKey, { expiresIn: "whenever" } );
            } catch ( x ) {
                expect( x.message ).toEqual( "\"expiresIn\" should be a number of seconds or string representing a timespan eg: \"1d\", \"20h\", 60" );
            }
        } );

    } );

    describe( "verify", () => {

        it( "works", async () => {
            const result = await jwtToken.verify( await jwtToken.sign( token, jwtKey ), jwtKey );
            expect( result ).toEqual( { ...token, "iat": expect.any( Number ) } );
        } );

        it( "throws exception if token is missing", async () => {
            expect.assertions( 1 );
            try {
                await jwtToken.verify( ( undefined: any ), jwtKey );
            } catch ( x ) {
                expect( x.message ).toEqual( "jwt must be provided" );
            }
        } );

        it( "throws exception if token expired", async () => {
            expect.assertions( 1 );
            const expiredToken = await jwtToken.sign( token, jwtKey, { expiresIn: "0s" } );
            try {
                await jwtToken.verify( expiredToken, jwtKey );
            } catch ( x ) {
                expect( x.name ).toEqual( "TokenExpiredError" );
            }
        } );

        it( "throws exception if token signature is invalid", async () => {
            expect.assertions( 1 );
            const invalidToken = await jwtToken.sign( token, "not-so-secret" );
            try {
                await jwtToken.verify( invalidToken, jwtKey );
            } catch ( x ) {
                expect( x.name ).toEqual( "JsonWebTokenError" );
            }
        } );

    } );

} );
