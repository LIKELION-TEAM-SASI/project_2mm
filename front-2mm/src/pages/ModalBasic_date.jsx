import React from "react";
import PropTypes from "prop-types";
import styles from "./ModalBasic_date.module.css";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

function ModalBasic({ setModalOpen, planID }) {
  const [plan, setPlan] = useState(null); // plan 상태 선언
  const navigate = useNavigate();
  // 모달 닫기
  const closeModal = () => {
    setModalOpen(false);
  };

  // 모달 밖을 클릭할 때 모달 닫기
  const handleOverlayClick = () => {
    closeModal();
  };

  // 모달 내부를 클릭해도 모달이 닫히지 않도록 처리
  const handleModalClick = (e) => {
    e.stopPropagation();
  };

  const deletePlan = () => {
    try {
      const token = localStorage.getItem("token");
      const headers = { Authorization: `Token ${token}` };
      const code = localStorage.getItem("code");
      // 이전 페이지에서 전달받은 코드를 불러와야 함. 그래야 클릭한 모임이 삭제됨 로컬스토리지에서 불러오지x
      axios
        .delete(`http://127.0.0.1:8000/group/${code}/plans/${planID}`, {
          headers,
        })
        .then((res) => {
          console.log(res);
          setPlan(plan.filter((e) => plan.code !== e.code)); // texts 배열 업데이트해서 해당 text.id와 일치하지 않는 데이터만 남도록 필터링
        })
        .catch((error) => {
          console.log(error);
          setModalOpen(false);
          // 페이지 새로고침
          window.location.reload();
        });
    } catch (error) {
      console.error("Error delete:", error);
    }
    setModalOpen(false);
    navigate("/Date_List");
  };

  return (
    <div className={styles.overlay} onClick={handleOverlayClick}>
      <div className={styles.container} onClick={handleModalClick}>
        <img
          className={styles.delete}
          src={`${process.env.PUBLIC_URL}/images/delete (3).svg`}
          alt="delete"
          onClick={deletePlan}
        />
        <img
          className={styles.cancel}
          src={`${process.env.PUBLIC_URL}/images/cancel (2).svg`}
          alt="cancel"
          onClick={closeModal} // 모달 닫기
        />
      </div>
    </div>
  );
}

ModalBasic.propTypes = {
  setModalOpen: PropTypes.func.isRequired,
};

export default ModalBasic;
