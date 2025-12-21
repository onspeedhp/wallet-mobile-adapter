/**
 * LazorKit Wallet Mobile Adapter - Store Actions
 *
 * This file contains the action functions for the wallet store.
 * These actions handle wallet connection, disconnection, and transaction signing.
 */
import { handleAuthRedirect } from './core/auth/handleRedirect';
import { openBrowser, openSignBrowser } from './core/browser/open';
import { handleBrowserResult } from './core/browser/parseResult';
import { createWalletActions } from './core/wallet/actions';
import { logger } from './core/logger';
import { Buffer } from 'buffer';
import { API_ENDPOINTS } from './config';
import * as anchor from '@coral-xyz/anchor';
import {
  WalletStateClient,
  ConnectOptions,
  SignOptions,
  WalletConnectionError,
  SigningError,
} from './types';
import { asCredentialHash, LazorkitClient, getBlockchainTimestamp, SmartWalletAction } from './contract';
import { getFeePayer } from './core/paymaster';
import { sha256 } from 'js-sha256';
import { SignAndSendTransactionPayload } from './types';

/**
 * Connects to the wallet
 *
 * @param get - Zustand state getter function
 * @param set - Zustand state setter function
 * @param options - Connection options with callbacks
 * @returns Promise that resolves to complete wallet information
 */
export const connectAction = async (
  get: () => WalletStateClient,
  set: (state: Partial<WalletStateClient>) => void,
  options: ConnectOptions
) => {
  const { isConnecting, config } = get();
  if (isConnecting) {
    logger.error('Connect attempt while already connecting');
    throw new WalletConnectionError('Already connecting');
  }

  set({ isConnecting: true, error: null });

  try {
    const redirectUrl = options.redirectUrl;
    const connectUrl = `${config.portalUrl}/${API_ENDPOINTS.CONNECT
      }&redirect_url=${encodeURIComponent(redirectUrl)}`;

    const resultUrl = await openBrowser(connectUrl, redirectUrl);
    const walletInfo = handleAuthRedirect(resultUrl);
    if (!walletInfo) {
      logger.error('Invalid wallet info from redirect', { resultUrl });
      throw new WalletConnectionError('Invalid wallet info from redirect');
    }

    const { saveWallet } = createWalletActions(
      get().connection,
      (isLoading) => set({ isLoading }),
      config
    );

    const savedWallet = await saveWallet(walletInfo);
    set({ wallet: savedWallet });
    return savedWallet;
  } catch (error: unknown) {
    const err = error instanceof Error ? error : new WalletConnectionError(String(error));
    logger.error('Connect action failed:', err, { redirectUrl: options.redirectUrl });
    set({ error: err });
    throw err;
  } finally {
    set({ isConnecting: false });
  }
};

/**
 * Disconnects from the wallet
 *
 * @param set - Zustand state setter function
 */
export const disconnectAction = async (set: (state: Partial<WalletStateClient>) => void) => {
  set({ isLoading: true });
  try {
    set({ wallet: null });
  } catch (error: unknown) {
    const err = error instanceof Error ? error : new Error(String(error));
    logger.error('Disconnect action failed:', err);
    set({ error: err });
    throw err;
  } finally {
    set({ isLoading: false });
  }
};

/**
 * Sign and execute transaction via Paymaster
 *
 * @param get - Zustand state getter function
 * @param set - Zustand state setter function
 * @param txnIns - Transaction instruction to execute
 * @param options - Signing options with callbacks
 */
export const signAndExecuteTransaction = async (
  get: () => WalletStateClient,
  set: (state: Partial<WalletStateClient>) => void,
  payload: SignAndSendTransactionPayload,
  options: SignOptions
) => {
  const { isSigning, connection, wallet, config } = get();
  if (isSigning) {
    return;
  }

  if (!wallet) {
    const error = new SigningError('No wallet connected');
    logger.error('Sign failed: No wallet connected');
    options?.onFail?.(error);
    return;
  }

  if (!connection) {
    const error = new SigningError('No connection available');
    logger.error('Sign failed: No connection available');
    options?.onFail?.(error);
    return;
  }

  set({ isSigning: true, error: null });

  try {
    const lazorProgram = new LazorkitClient(connection);

    const feePayer = await getFeePayer(config.configPaymaster.paymasterUrl, config.configPaymaster.apiKey);

    const timestamp = new anchor.BN(await getBlockchainTimestamp(connection));

    const message = await lazorProgram.buildAuthorizationMessage({
      action: {
        type: SmartWalletAction.CreateChunk,
        args: {
          cpiInstructions: payload.instructions,
        }
      },
      payer: feePayer,
      smartWallet: new anchor.web3.PublicKey(wallet.smartWallet),
      passkeyPublicKey: wallet.passkeyPubkey,
      timestamp,
      credentialHash: asCredentialHash(
        Array.from(
          new Uint8Array(
            sha256.arrayBuffer(Buffer.from(wallet.credentialId, 'base64'))
          )
        )
      ),
    });

    const encodedChallenge = Buffer.from(message)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const latestBlockhash = await connection.getLatestBlockhash();
    const messageV0 = new anchor.web3.TransactionMessage({
      payerKey: feePayer, // PublicKey
      recentBlockhash: latestBlockhash.blockhash,
      instructions: payload.instructions,
    }).compileToV0Message();

    const versionedTx = new anchor.web3.VersionedTransaction(messageV0);
    const base64Tx = Buffer.from(versionedTx.serialize()).toString("base64");
    const redirectUrl = options.redirectUrl;
    let signUrl = `${config.portalUrl}/${API_ENDPOINTS.SIGN}&message=${encodeURIComponent(
      encodedChallenge
    )}&credentialId=${encodeURIComponent(wallet.credentialId)}&transaction=${encodeURIComponent(base64Tx)}&redirect_url=${encodeURIComponent(redirectUrl)}`;

    if (payload.transactionOptions?.clusterSimulation) {
      signUrl += `&clusterSimulation=${payload.transactionOptions.clusterSimulation}`;
    }

    await openSignBrowser(
      signUrl,
      redirectUrl,
      async (urlResult) => {
        try {
          const browserResult = handleBrowserResult(urlResult);
          const walletActions = createWalletActions(
            connection,
            (isLoading) => set({ isLoading }),
            config
          );

          const txnSignature = await walletActions.executeWallet(
            wallet,
            feePayer,
            timestamp,
            {
              type: SmartWalletAction.CreateChunk,
              args: {
                cpiInstructions: payload.instructions,
              }
            },
            browserResult,
            options,
            payload.transactionOptions
          );
          options?.onSuccess?.(txnSignature);
        } catch (error) {
          const err = error instanceof Error ? error : new Error(String(error));
          logger.error('Sign browser result processing failed:', err, { urlResult });
          set({ error: err });
          options?.onFail?.(err);
        }
      },
      (error) => {
        logger.error('Sign browser failed:', error, { signUrl, redirectUrl });
        set({ error });
        options?.onFail?.(error);
      }
    );
  } catch (error: unknown) {
    logger.error('Sign message action failed:', error, {
      smartWallet: wallet?.smartWallet,
      redirectUrl: options.redirectUrl,
    });
    const err = error instanceof Error ? error : new SigningError('Unknown error');
    set({ error: err });
    options?.onFail?.(err);
  } finally {
    set({ isSigning: false });
  }
};

/**
 * Sign a message (arbitrary string or bytes)
 *
 * @param get - Zustand state getter function
 * @param set - Zustand state setter function
 * @param message - Message to sign (string)
 * @param options - Signing options with callbacks
 */
export const signMessageAction = async (
  get: () => WalletStateClient,
  set: (state: Partial<WalletStateClient>) => void,
  message: string,
  options: SignOptions
) => {
  const { isSigning, wallet, config } = get();
  if (isSigning) {
    return;
  }

  if (!wallet) {
    const error = new SigningError('No wallet connected');
    logger.error('Sign message failed: No wallet connected');
    options?.onFail?.(error);
    return;
  }

  set({ isSigning: true, error: null });

  try {
    const redirectUrl = options.redirectUrl;
    // For signMessage, we pass the message directly.
    // The portal will treat 'transaction' param as message if it's not a valid transaction or if action is 'sign'
    // But better to use a specific param or just rely on 'transaction' param being the message container as per portal logic
    // PortalCommunicator: transaction: urlParams.get('transaction')
    // TransactionReview: portalParams.transaction || portalParams.message
    // Let's use 'message' param for clarity if portal supports it, checking portal-communicator.ts:
    // message: urlParams.get('message') || ''
    // So we should use 'message' param.

    // If message is not base64, we might want to encode it?
    // User passes string. Let's pass it as is, or base64 encoded?
    // Portal expects 'message' to be displayed. If we want it to be readable, pass as string.
    // If it's bytes, pass base64?
    // The type signature says `message: string`. Let's assume readable string.

    const signUrl = `${config.portalUrl}/${API_ENDPOINTS.SIGN}&message=${encodeURIComponent(
      message
    )}&credentialId=${encodeURIComponent(wallet.credentialId)}&redirect_url=${encodeURIComponent(redirectUrl)}`;

    await openSignBrowser(
      signUrl,
      redirectUrl,
      async (urlResult) => {
        try {
          const authResult = handleBrowserResult(urlResult);
          const signature = authResult.signature;
          const signedPayload = authResult.message;
          options?.onSuccess?.({ signature, signedPayload });
        } catch (error) {
          const err = error instanceof Error ? error : new Error(String(error));
          logger.error('Sign message browser result processing failed:', err, { urlResult });
          set({ error: err });
          options?.onFail?.(err);
        }
      },
      (error) => {
        logger.error('Sign message browser failed:', error, { signUrl, redirectUrl });
        set({ error });
        options?.onFail?.(error);
      }
    );
  } catch (error: unknown) {
    logger.error('Sign message action failed:', error, {
      smartWallet: wallet?.smartWallet,
      redirectUrl: options.redirectUrl,
    });
    const err = error instanceof Error ? error : new SigningError('Unknown error');
    set({ error: err });
    options?.onFail?.(err);
  } finally {
    set({ isSigning: false });
  }
};
