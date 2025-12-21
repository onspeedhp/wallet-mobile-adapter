/**
 * LazorKit Wallet Mobile Adapter - Wallet Actions (core)
 *
 * Pure functions that interact with the LazorKit on-chain program. No React or
 * Zustand dependencies here. The consumer is expected to provide their own
 * loading state handler via callbacks.
 */

import * as anchor from '@coral-xyz/anchor';
import { Buffer } from 'buffer';
import { WalletInfo, BrowserResult, WalletActions, SignOptions } from '../../types';
import {
  ArgsByAction,
  LazorkitClient,
  SmartWalletActionArgs,
  SmartWalletAction,
  asCredentialHash,
  asPasskeyPublicKey,
  ensureChunkExist
} from '../../contract';
import { getFeePayer, signAndExecuteTransaction } from '../paymaster';
import { logger } from '../logger';
import { sha256 } from 'js-sha256';

/**
 * Factory that returns high-level wallet operations bound to a given
 * Connection and loading-state setter.
 */
export const createWalletActions = (
  connection: anchor.web3.Connection,
  setLoading: (isLoading: boolean) => void,
  config: { configPaymaster: { paymasterUrl: string, apiKey?: string } }
): WalletActions => {
  const lazorProgram = new LazorkitClient(connection);

  /**
   * Ensures the smart wallet exists on-chain, creating it if needed.
   */
  const saveWallet = async (data: WalletInfo): Promise<WalletInfo> => {
    setLoading(true);
    try {
      // Compute credential hash
      const credentialHash = asCredentialHash(
        Array.from(
          new Uint8Array(
            sha256.arrayBuffer(Buffer.from(data.credentialId, 'base64'))
          )
        )
      );

      // Fetch initial wallet state
      let walletState = await lazorProgram.getSmartWalletByCredentialHash(credentialHash);

      let smartWallet: anchor.web3.PublicKey | undefined;
      let walletDevice: anchor.web3.PublicKey | undefined;

      if (!walletState) {
        // === Create new smart wallet on chain ===
        const feePayer = await getFeePayer(config.configPaymaster.paymasterUrl, config.configPaymaster.apiKey);

        const result = await lazorProgram.createSmartWalletTxn({
          passkeyPublicKey: asPasskeyPublicKey(data.passkeyPubkey),
          payer: feePayer,
          credentialIdBase64: data.credentialId,
        });

        const serialized = result.transaction
          .serialize({ verifySignatures: false, requireAllSignatures: false })
          .toString('base64');

        const signature = await signAndExecuteTransaction(
          serialized,
          config.configPaymaster.paymasterUrl,
          feePayer.toBase58(),
          config.configPaymaster.apiKey,
        )

        if (!signature) {
          logger.error('Create wallet relayer error:', {
            paymasterUrl: config.configPaymaster.paymasterUrl,
          });
          throw new Error(`Create wallet relayer error`);
        }

        await lazorProgram.connection.confirmTransaction(
          String(signature),
          'confirmed'
        );

        walletState = await lazorProgram.getSmartWalletByCredentialHash(credentialHash);

        if (!walletState) {
          logger.error(
            'Failed to create smart wallet on chain after transaction confirmed',
            {
              signature,
              passkeyPubkey: data.passkeyPubkey,
            }
          );
          throw new Error('Failed to create smart wallet on chain');
        }
      }

      smartWallet = walletState.smartWallet;
      walletDevice = walletState.walletDevice;

      if (!smartWallet || !walletDevice) {
        throw new Error('Smart wallet or wallet device is undefined after processing.');
      }

      // If passkeyPubkey was missing (e.g. from redirect), update it from on-chain state
      const initialPasskeyPubkey = data.passkeyPubkey;
      const finalPasskeyPubkey = initialPasskeyPubkey.length === 0 && walletState.passkeyPublicKey
        ? Array.from(walletState.passkeyPublicKey)
        : initialPasskeyPubkey;

      return {
        ...data,
        passkeyPubkey: finalPasskeyPubkey,
        smartWallet: smartWallet.toString(),
        walletDevice: walletDevice.toString(),
      };
    } catch (error) {
      logger.error('SaveWallet action failed:', error, { walletData: data });
      throw error;
    } finally {
      setLoading(false);
    }
  };

  /**
   * Executes a wallet instruction through the LazorKit program using WebAuthn
   * signature pieces provided by the browser flow.
   */
  const executeWallet = async (
    data: WalletInfo,
    feePayer: anchor.web3.PublicKey,
    timestamp: anchor.BN,
    action: SmartWalletActionArgs,
    browserResult: BrowserResult,
    signOptions: SignOptions,
    transactionOptions: { feeToken?: string; addressLookupTableAccounts?: anchor.web3.AddressLookupTableAccount[]; computeUnitLimit?: number; }
  ): Promise<string> => {
    setLoading(true);
    const credentialHash = asCredentialHash(
      Array.from(
        new Uint8Array(
          sha256.arrayBuffer(Buffer.from(data.credentialId, 'base64'))
        )
      )
    );
    try {
      const { policyInstruction, cpiInstructions } =
        action.args as ArgsByAction[SmartWalletAction.CreateChunk];

      // Use provided ALTs directly

      const createChunkTransaction = await lazorProgram.createChunkTxn(
        {
          payer: feePayer,
          smartWallet: new anchor.web3.PublicKey(data.smartWallet),
          passkeySignature: {
            passkeyPublicKey: asPasskeyPublicKey(data.passkeyPubkey),
            signature64: browserResult.signature,
            clientDataJsonRaw64: browserResult.clientDataJsonBase64,
            authenticatorDataRaw64: browserResult.authenticatorDataBase64,
          },
          policyInstruction,
          cpiInstructions,
          timestamp,
          credentialHash,
        },
      ) as anchor.web3.Transaction;

      const signature = await signAndExecuteTransaction(
        Buffer.from(createChunkTransaction.serialize({ verifySignatures: false, requireAllSignatures: false })).toString('base64'),
        config.configPaymaster.paymasterUrl,
        feePayer.toBase58(),
        config.configPaymaster.apiKey,
        transactionOptions?.feeToken
      );
      await lazorProgram.connection.confirmTransaction(
        String(signature),
        'confirmed'
      );

      await ensureChunkExist(
        lazorProgram.connection,
        lazorProgram,
        new anchor.web3.PublicKey(data.smartWallet)
      );

      const addressLookupTables = transactionOptions?.addressLookupTableAccounts || [];
      const executeChunkTransaction = await lazorProgram.executeChunkTxn({
        payer: feePayer,
        smartWallet: new anchor.web3.PublicKey(data.smartWallet),
        cpiInstructions,
      }, {
        computeUnitLimit: transactionOptions?.computeUnitLimit,
        addressLookupTables: addressLookupTables,
      });
      const signatureExecuteChunk = await signAndExecuteTransaction(
        addressLookupTables.length > 0 ? Buffer.from(executeChunkTransaction.serialize()).toString('base64') : Buffer.from(executeChunkTransaction.serialize({ verifySignatures: false, requireAllSignatures: false })).toString('base64'),
        config.configPaymaster.paymasterUrl,
        feePayer.toBase58(),
        config.configPaymaster.apiKey,
        transactionOptions?.feeToken
      );

      await lazorProgram.connection.confirmTransaction(
        String(signatureExecuteChunk),
        'confirmed'
      );
      return signatureExecuteChunk;
    } catch (error: unknown) {
      logger.error('ExecuteWallet action failed:', error, {
        smartWallet: data.smartWallet,
      });
      const err = error instanceof Error ? error : new Error(String(error));
      throw err;
    } finally {
      setLoading(false);
    }
  };
  return {
    saveWallet,
    executeWallet,
  };
};
