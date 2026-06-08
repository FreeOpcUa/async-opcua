# Interface Contracts: Session Actor Messages

This document defines the message contracts used for communication between connection loops/publish threads and the isolated session actors.

---

## 1. Message: Read Request

Requests the session actor to retrieve the value of a specific node attribute.

### Fields
*   **Node Identifier**: The ID of the target node to read.
*   **Attribute Identifier**: The specific attribute to read (e.g., Value, DisplayName).
*   **Response Channel**: An asynchronous callback channel to return the operation result.

### Expected Responses
*   **Success**: The retrieved attribute value and status code.
*   **Failure**: An error status code (e.g., Node ID unknown, Insufficient permissions).

---

## 2. Message: Write Request

Requests the session actor to modify the value of a specific node attribute.

### Fields
*   **Node Identifier**: The ID of the target node to modify.
*   **Attribute Identifier**: The specific attribute to write.
*   **Data Value**: The new value and timestamp to write.
*   **Response Channel**: An asynchronous callback channel to return the write status.

### Expected Responses
*   **Success**: Confirmation status code.
*   **Failure**: Error status code (e.g., ReadOnly, TypeMismatch).

---

## 3. Message: Publish Request

Requests the session actor to gather change notifications for the active subscriptions.

### Fields
*   **Subscription Identifier**: The active subscription ID.
*   **Response Channel**: A callback channel returning the compiled notification frame.

### Expected Responses
*   **Success**: Compiled notification message containing values.
*   **Failure**: Error status code (e.g., Subscription expired).

---

## 4. Message: Terminate Session

Signals the session actor to clean up its state and shut down immediately.

### Fields
*   **Reason Code**: The cause for termination (e.g., Client disconnect, timeout).
*   **Acknowledge Channel**: Callback channel to notify the session manager when cleanup is complete.
