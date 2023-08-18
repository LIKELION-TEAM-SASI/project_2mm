import { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useEffect } from "react";
import axios from "axios";
const BACKEND_URL =
  "https://uuju.pythonanywhere.com" || "http://127.0.0.1:8000";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: 30px auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const Title = styled.div`
  position: relative;
  top: -23px;
  left: 150px;
`;

const SubTitle = styled.div`
  position: relative;
  color: #000;
  font-family: Inter;
  font-size: 26px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
  top: 25px;
  left: 25px;
`;

const Group_O = styled.div`
  position: relative;
  top: 60px;
  left: 22px;
  cursor: pointer; /* 추가: 클릭 가능한 커서 스타일 설정 */
`;

const Group_X = styled.div`
  position: relative;
  top: 70px;
  left: 22px;
  cursor: pointer; /* 추가: 클릭 가능한 커서 스타일 설정 */
`;

const NextBtn = styled.div`
  position: relative;
  top: 298px;
  left: 22px;
`;

const Membership4 = () => {
  const navigate = useNavigate();
  const [isGroupOClicked, setIsGroupOClicked] = useState(false);
  const [isGroupXClicked, setIsGroupXClicked] = useState(false);

  const onClickGroupO = () => {
    setIsGroupOClicked(true);
    setIsGroupXClicked(false);
  };

  const onClickGroupX = () => {
    setIsGroupXClicked(true);
    setIsGroupOClicked(false);
  };

  const onClickSign = () => {
    if (isGroupOClicked) {
      navigate("/Signup1_old");
    } else if (isGroupXClicked) {
      navigate("/Signup1_new");
    }
  };

  // 로그인한 유저 이름 받아오기
  const [user, setUser] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem("token"); // 로컬 스토리지에서 토큰 가져옴
    const headers = { Authorization: `Token ${token}` }; // 헤더에 토큰 추가
    axios.get(`${BACKEND_URL}/get-username/`, { headers }).then((response) => {
      setUser(response.data);
      console.log(user);
    });
  }, []);

  return (
    <Container>
      <Back>&nbsp;</Back>
      <Title></Title>
      <SubTitle>
        {user && user.username}님, <br />
        참여할 모임이 있으신가요?
      </SubTitle>
      <Group_O onClick={onClickGroupO}>
        <img
          src={
            isGroupOClicked
              ? `${BACKEND_URL}/images/group_o_b.svg`
              : `${BACKEND_URL}/images/group_o.svg`
          }
          alt="group_o"
        />
      </Group_O>
      <Group_X onClick={onClickGroupX}>
        <img
          src={
            isGroupXClicked
              ? `${BACKEND_URL}/images/group_x_b.svg`
              : `${BACKEND_URL}/images/group_x.svg`
          }
          alt="group_x"
        />
      </Group_X>
      <NextBtn onClick={onClickSign}>
        <img src={`${BACKEND_URL}/images/next_btn.svg`} alt="btn" />
      </NextBtn>
    </Container>
  );
};

export default Membership4;
