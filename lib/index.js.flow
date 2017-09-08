// @flow
import jsonWebToken from "jsonwebtoken";

export type JWT = { [string]: any };

export type SignOptions = {
    expiresIn?: number | string,
    noTimestamp?: boolean
};

export type VerifyOptions = {
    ignoreExpiration?: boolean
};


const mergeOptions = options => ( { ...( options || {} ), algorithm: "HS256" } );


export function sign( token: JWT, signatureKey: string, options?: SignOptions ): Promise<string> {
    return new Promise( ( resolve, reject ) => {
        jsonWebToken.sign(
            token,
            signatureKey,
            mergeOptions( options ),
            ( error, encodedToken ) => {
                if ( !error ) {
                    resolve( encodedToken );
                    return;
                }
                reject( error );
            }
        );
    } );
}

export function verify( encodedToken: string, signatureKey: string, options?: VerifyOptions ): Promise<JWT> {
    return new Promise( ( resolve, reject ) => {
        jsonWebToken.verify(
            encodedToken,
            signatureKey,
            mergeOptions( options ),
            ( error, token ) => {
                if ( !error ) {
                    resolve( token );
                    return;
                }
                reject( error );
            }
        );
    } );
}
